package launch

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gatelock/internal/redact"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of a Record.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func sh(script string) []string { return []string{"/bin/sh", "-c", script} }

func TestRunsWithEnvCwdAndStdin(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	var record syncBuffer
	code, err := Run(Spec{
		Argv:   sh(`echo "token=$TOKEN"; pwd -P; cat; echo oops >&2`),
		Cwd:    dir,
		Env:    []string{"TOKEN=sk_live_123", "PATH=/usr/bin:/bin"},
		Redact: []redact.Secret{{Label: "dev/TOKEN", Value: []byte("sk_live_123")}},
		Stdin:  strings.NewReader("from stdin\n"),
		Stdout: &stdout,
		Stderr: &stderr,
		Record: &record,
	}, func(int) {}, nil)
	if err != nil || code != 0 {
		t.Fatalf("code %d, err %v", code, err)
	}
	out := stdout.String()
	if !strings.Contains(out, "token=[REDACTED:dev/TOKEN]\n") || strings.Contains(out, "sk_live") {
		t.Errorf("stdout not masked: %q", out)
	}
	if !strings.Contains(out, "from stdin\n") {
		t.Errorf("stdin not passed: %q", out)
	}
	realDir, _ := filepath.EvalSymlinks(dir)
	if lines := strings.Split(out, "\n"); lines[1] != realDir {
		t.Errorf("cwd: %q, want %s", lines[1], realDir)
	}
	if stderr.String() != "oops\n" {
		t.Errorf("stderr: %q", stderr.String())
	}
	if rec := record.String(); !strings.Contains(rec, "[REDACTED:dev/TOKEN]") || !strings.Contains(rec, "oops") || strings.Contains(rec, "sk_live") {
		t.Errorf("record: %q", rec)
	}
}

func TestExitCodes(t *testing.T) {
	for script, want := range map[string]int{
		"exit 0":        0,
		"exit 3":        3,
		"kill -TERM $$": 128 + int(syscall.SIGTERM),
	} {
		code, err := Run(Spec{Argv: sh(script), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, func(int) {}, nil)
		if err != nil || code != want {
			t.Errorf("%s: code %d, err %v; want %d", script, code, err, want)
		}
	}
}

func TestCommandNotFound(t *testing.T) {
	code, err := Run(Spec{Argv: []string{"gatelock-no-such-command"}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, func(int) {
		t.Error("started called")
	}, nil)
	if code != 127 || err == nil {
		t.Fatalf("code %d, err %v", code, err)
	}
}

// groupGone reports whether no process is left in the group.
func groupGone(pgid int) bool { return syscall.Kill(-pgid, 0) == syscall.ESRCH }

func TestStopKillsProcessTree(t *testing.T) {
	stop := make(chan struct{})
	var pgid int
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(stop)
	}()
	code, err := Run(Spec{Argv: sh("sleep 30 & sleep 30; wait"), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		func(id int) { pgid = id }, stop)
	if err != nil || code != 128+int(syscall.SIGTERM) {
		t.Fatalf("code %d, err %v", code, err)
	}
	if !groupGone(pgid) {
		t.Fatal("processes left in the group")
	}
}

func TestStopKillsCommandIgnoringSIGTERM(t *testing.T) {
	killDelay = 300 * time.Millisecond
	defer func() { killDelay = 5 * time.Second }()

	for name, ask := range map[string]func(stop chan struct{}){
		"stop":    func(stop chan struct{}) { close(stop) },
		"SIGTERM": func(chan struct{}) { syscall.Kill(os.Getpid(), syscall.SIGTERM) },
	} {
		stop := make(chan struct{})
		var pgid int
		var stdout bytes.Buffer
		started := make(chan struct{})
		go func() {
			<-started
			time.Sleep(200 * time.Millisecond) // let the trap be set
			ask(stop)
		}()
		begin := time.Now()
		code, err := Run(Spec{Argv: sh(`trap 'echo ignored' TERM; while :; do sleep 0.05; done`), Stdout: &stdout, Stderr: &bytes.Buffer{}},
			func(id int) { pgid = id; close(started) }, stop)
		if err != nil || code != 128+int(syscall.SIGKILL) {
			t.Errorf("%s: code %d, err %v", name, code, err)
		}
		if elapsed := time.Since(begin); elapsed > 3*time.Second {
			t.Errorf("%s: took %v", name, elapsed)
		}
		if !strings.Contains(stdout.String(), "ignored") {
			t.Errorf("%s: SIGTERM not delivered first: %q", name, stdout.String())
		}
		if !groupGone(pgid) {
			t.Errorf("%s: processes left in the group", name)
		}
	}
}

func TestSecondSignalKillsAtOnce(t *testing.T) {
	var pgid int
	started := make(chan struct{})
	go func() {
		<-started
		time.Sleep(200 * time.Millisecond)
		syscall.Kill(os.Getpid(), syscall.SIGINT)
		time.Sleep(100 * time.Millisecond)
		syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()
	begin := time.Now()
	code, _ := Run(Spec{Argv: sh(`trap '' INT TERM; while :; do sleep 0.05; done`), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		func(id int) { pgid = id; close(started) }, nil)
	if code != 128+int(syscall.SIGKILL) {
		t.Fatalf("code %d", code)
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("took %v, want well under killDelay", elapsed)
	}
	if !groupGone(pgid) {
		t.Fatal("processes left in the group")
	}
}
