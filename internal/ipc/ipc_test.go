package ipc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gatelock/internal/history"
	"gatelock/internal/launch"
	"gatelock/internal/redact"
	"gatelock/internal/vault"
)

type auth struct {
	deny bool
	hold chan struct{}
}

func (a *auth) ConfirmUser(ctx context.Context, reason string) error {
	if a.hold != nil {
		select {
		case <-a.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if a.deny {
		return vault.ErrDenied
	}
	return nil
}

func (a *auth) AskPassphrase(context.Context, string, string, bool) ([]byte, error) {
	return nil, vault.ErrDenied
}

type keychain map[string][]byte

func (k keychain) Get(a string) ([]byte, error) {
	if v, ok := k[a]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}
func (k keychain) Set(a string, v []byte) error { k[a] = v; return nil }
func (k keychain) Delete(a string) error        { delete(k, a); return nil }

// trackingListener remembers the connections it accepts, so that a test
// can break them as an app quitting would.
type trackingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *trackingListener) breakAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		c.Close()
	}
}

type app struct {
	socket  string
	history *history.Store
	l       *trackingListener
	cwd     string
}

func startApp(t *testing.T, a *auth) *app {
	t.Helper()
	// Socket paths are short on macOS; t.TempDir's are too long.
	sockDir, err := os.MkdirTemp("/tmp", "gl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	data := t.TempDir()
	v, err := vault.Open(filepath.Join(data, "vaults"), keychain{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create("prod", []byte("pw"), true, vault.Policy{Mode: vault.Every}); err != nil {
		t.Fatal(err)
	}
	v.SetEnv("prod", "TOKEN", []byte("sk_live_123"))
	h, err := history.Open(filepath.Join(data, "activities"), func() {})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockDir, "s")
	l, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	tl := &trackingListener{Listener: l}
	go Serve(tl, v, h)
	t.Cleanup(func() { l.Close() })
	return &app{socket: socket, history: h, l: tl, cwd: t.TempDir()}
}

func noStart() error { return errors.New("not started in tests") }

// runCLI does what `gatelock run` does, returning its exit code and stdout.
func runCLI(t *testing.T, a *app, argv ...string) (int, string, error) {
	t.Helper()
	nc, err := Dial(a.socket, noStart)
	if err != nil {
		t.Fatal(err)
	}
	s, secrets, err := Run(nc, RunRequest{Vault: "prod", Argv: argv, Cwd: a.cwd})
	if err != nil {
		return 0, "", err
	}
	env := []string{"PATH=/usr/bin:/bin"}
	var masks []redact.Secret
	for _, sec := range secrets {
		env = append(env, sec.Key+"="+string(sec.Value))
		masks = append(masks, redact.Secret{Label: "prod/" + sec.Key, Value: sec.Value})
	}
	var stdout bytes.Buffer
	code, err := launch.Run(launch.Spec{
		Argv: argv, Cwd: a.cwd, Env: env, Redact: masks,
		Stdout: &stdout, Stderr: &bytes.Buffer{}, Record: s,
	}, s.Started, s.Stop())
	if err != nil {
		s.Failed(err)
		return code, stdout.String(), nil
	}
	s.Exit(code)
	return code, stdout.String(), nil
}

// waitFor waits for the latest activity to reach status.
func waitFor(t *testing.T, h *history.Store, status history.Status) history.Activity {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if activities := h.List(); len(activities) > 0 && activities[0].Status == status {
			return activities[0]
		}
	}
	t.Fatalf("no activity reached %s: %+v", status, h.List())
	return history.Activity{}
}

func TestRun(t *testing.T) {
	a := startApp(t, &auth{})
	code, stdout, err := runCLI(t, a, "/bin/sh", "-c", `echo "token=$TOKEN"; exit 4`)
	if err != nil || code != 4 {
		t.Fatalf("code %d, err %v", code, err)
	}
	if stdout != "token=[REDACTED:prod/TOKEN]\n" {
		t.Fatalf("stdout %q", stdout)
	}
	r := waitFor(t, a.history, history.Exited)
	// The CLI here is the test, run by go test at least.
	if r.ExitCode != 4 || r.Vault != "prod" || r.PGID == 0 || r.Caller == "" {
		t.Fatalf("activity %+v", r)
	}
	if out, _ := a.history.Output(r.ID); string(out) != "token=[REDACTED:prod/TOKEN]\n" {
		t.Fatalf("recorded %q", out)
	}
}

// The app keeps none of the output of a run asked not to record it, even
// if the CLI sends it.
func TestNoRecordOutput(t *testing.T) {
	a := startApp(t, &auth{})
	nc, err := Dial(a.socket, noStart)
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"echo", "hi"}
	s, _, err := Run(nc, RunRequest{Vault: "prod", Argv: argv, Cwd: a.cwd, NoRecordOutput: true})
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	code, err := launch.Run(launch.Spec{
		Argv: argv, Cwd: a.cwd, Env: []string{"PATH=/usr/bin:/bin"},
		Stdout: &stdout, Stderr: &bytes.Buffer{}, Record: s,
	}, s.Started, s.Stop())
	if err != nil || code != 0 {
		t.Fatalf("code %d, err %v", code, err)
	}
	s.Exit(code)
	if stdout.String() != "hi\n" {
		t.Fatalf("stdout %q", stdout.String())
	}
	r := waitFor(t, a.history, history.Exited)
	if !r.OutputNotRecorded {
		t.Fatalf("activity %+v", r)
	}
	if out, _ := a.history.Output(r.ID); len(out) != 0 {
		t.Fatalf("recorded %q", out)
	}
}

func TestCommandNotFound(t *testing.T) {
	a := startApp(t, &auth{})
	if code, _, err := runCLI(t, a, "gatelock-no-such-command"); code != 127 || err != nil {
		t.Fatalf("code %d, err %v", code, err)
	}
	waitFor(t, a.history, history.Failed)
}

func TestDenied(t *testing.T) {
	a := startApp(t, &auth{deny: true})
	if _, _, err := runCLI(t, a, "true"); !errors.Is(err, vault.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	waitFor(t, a.history, history.Denied)
}

func TestAuthorizingIsRecorded(t *testing.T) {
	au := &auth{hold: make(chan struct{})}
	a := startApp(t, au)
	done := make(chan struct{})
	go func() {
		runCLI(t, a, "true")
		close(done)
	}()
	waitFor(t, a.history, history.Authorizing)
	close(au.hold)
	<-done
	waitFor(t, a.history, history.Exited)
}

func TestVaultNotFound(t *testing.T) {
	a := startApp(t, &auth{})
	nc, _ := Dial(a.socket, noStart)
	_, _, err := Run(nc, RunRequest{Vault: "nope", Argv: []string{"true"}, Cwd: a.cwd})
	if !errors.Is(err, vault.ErrNotFound) || !strings.Contains(err.Error(), "prod") {
		t.Fatalf("got %v", err)
	}
	if activities := a.history.List(); len(activities) != 0 {
		t.Fatalf("recorded %+v", activities)
	}
}

func TestInvalidCwd(t *testing.T) {
	a := startApp(t, &auth{})
	for _, cwd := range []string{"relative", "/no/such/dir"} {
		nc, _ := Dial(a.socket, noStart)
		if _, _, err := Run(nc, RunRequest{Vault: "prod", Argv: []string{"true"}, Cwd: cwd}); err == nil {
			t.Errorf("cwd %q accepted", cwd)
		}
	}
}

func TestStopFromApp(t *testing.T) {
	a := startApp(t, &auth{})
	go func() {
		r := waitFor(t, a.history, history.Running)
		time.Sleep(200 * time.Millisecond)
		a.history.Stop(r.ID)
	}()
	code, _, err := runCLI(t, a, "/bin/sh", "-c", "sleep 30")
	if err != nil || code != 128+int(syscall.SIGTERM) {
		t.Fatalf("code %d, err %v", code, err)
	}
	waitFor(t, a.history, history.Stopped)
}

func TestCLIKilledStopsCommand(t *testing.T) {
	a := startApp(t, &auth{})
	nc, _ := Dial(a.socket, noStart)
	s, _, err := Run(nc, RunRequest{Vault: "prod", Argv: []string{"sleep", "30"}, Cwd: a.cwd})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.Started(cmd.Process.Pid)
	time.Sleep(100 * time.Millisecond)
	// Gone as if killed: no exit reported.
	nc.Close()
	done := make(chan error)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		t.Fatal("command left running")
	}
	waitFor(t, a.history, history.Lost)
}

func TestAppGoneStopsCommand(t *testing.T) {
	a := startApp(t, &auth{})
	go func() {
		waitFor(t, a.history, history.Running)
		time.Sleep(200 * time.Millisecond)
		a.l.breakAll()
	}()
	nc, _ := Dial(a.socket, noStart)
	s, _, err := Run(nc, RunRequest{Vault: "prod", Argv: []string{"sleep", "30"}, Cwd: a.cwd})
	if err != nil {
		t.Fatal(err)
	}
	code, err := launch.Run(launch.Spec{Argv: []string{"sleep", "30"}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Record: s},
		s.Started, s.Stop())
	if err != nil || code != 128+int(syscall.SIGTERM) || !s.Lost() {
		t.Fatalf("code %d, err %v, lost %v", code, err, s.Lost())
	}
	waitFor(t, a.history, history.Lost)
}

func TestAppGoneWhileAuthorizing(t *testing.T) {
	au := &auth{hold: make(chan struct{})}
	defer close(au.hold)
	a := startApp(t, au)
	go func() {
		waitFor(t, a.history, history.Authorizing)
		a.l.breakAll()
	}()
	nc, _ := Dial(a.socket, noStart)
	if _, _, err := Run(nc, RunRequest{Vault: "prod", Argv: []string{"true"}, Cwd: a.cwd}); err == nil {
		t.Fatal("run granted")
	}
	waitFor(t, a.history, history.Lost)
}

func TestRecordNeverBlocks(t *testing.T) {
	// A session whose app never reads: its writes must still return.
	client, server := net.Pipe()
	defer server.Close()
	s := &Session{c: newConn(client), frames: make(chan frame, 2), sent: make(chan struct{}), stop: make(chan struct{})}
	go s.send()
	done := make(chan struct{})
	go func() {
		for range 1000 {
			s.Write([]byte("output"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked")
	}
}

func TestStopWhileAuthorizing(t *testing.T) {
	au := &auth{hold: make(chan struct{})}
	defer close(au.hold)
	a := startApp(t, au)
	go func() {
		r := waitFor(t, a.history, history.Authorizing)
		a.history.Stop(r.ID)
	}()
	nc, _ := Dial(a.socket, noStart)
	_, _, err := Run(nc, RunRequest{Vault: "prod", Argv: []string{"true"}, Cwd: a.cwd})
	if err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("got %v", err)
	}
	waitFor(t, a.history, history.Stopped)
}

func TestPeer(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "gl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	l, err := Listen(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cc, err := net.Dial("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	sc, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if pid, ok := peer(sc); !ok || pid != os.Getpid() {
		t.Fatalf("peer: %d, %v", pid, ok)
	}
	// Closed before it is looked at, as breaking connections can.
	sc.Close()
	if _, ok := peer(sc); ok {
		t.Fatal("a closed connection's peer passed")
	}
}
