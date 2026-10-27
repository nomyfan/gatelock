// Package launch runs a command with secrets in its environment, masking
// them in its output, the way `gatelock run` does.
package launch

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"gatelock/internal/redact"
)

// killDelay is how long a command has to exit after being asked to stop,
// before it is killed. Tests shorten it.
var killDelay = 5 * time.Second

// Spec describes a command to run.
type Spec struct {
	Argv   []string
	Cwd    string
	Env    []string // the command's whole environment
	Redact []redact.Secret
	Stdin  io.Reader
	// Stdout and Stderr receive the command's output, masked.
	Stdout, Stderr io.Writer
	// Record, if not nil, receives the masked stdout and stderr together
	// in the order written. It must not block, and must be safe from
	// several goroutines.
	Record io.Writer
}

// Run runs the command in a process group of its own and waits for it.
// started is called with the group's id once the command starts.
//
// SIGINT, SIGTERM and SIGHUP sent to this process are passed on to the
// group, and closing stop sends it SIGTERM. Either way, the group is
// killed if it is still there killDelay later, or at once on a second
// signal.
//
// The exit code follows the shell's: the command's own, 128 plus the signal
// that killed it, or 127 with an error if it could not be started.
func Run(s Spec, started func(pgid int), stop <-chan struct{}) (int, error) {
	cmd := exec.Command(s.Argv[0], s.Argv[1:]...)
	cmd.Dir = s.Cwd
	cmd.Env = s.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	record := s.Record
	if record == nil {
		record = io.Discard
	}
	stdout := redact.NewWriter(io.MultiWriter(s.Stdout, record), s.Redact)
	stderr := redact.NewWriter(io.MultiWriter(s.Stderr, record), s.Redact)
	cmd.Stdout, cmd.Stderr = stdout, stderr

	// In its own process group, the command would be stopped by SIGTTIN on
	// reading a terminal; this process, in the foreground, reads it instead.
	var stdinPipe io.WriteCloser
	if isTerminal(s.Stdin) {
		var err error
		if stdinPipe, err = cmd.StdinPipe(); err != nil {
			return 127, err
		}
	} else {
		cmd.Stdin = s.Stdin
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	if err := cmd.Start(); err != nil {
		return 127, err
	}
	pgid := cmd.Process.Pid
	started(pgid)
	if stdinPipe != nil {
		go func() {
			io.Copy(stdinPipe, s.Stdin)
			stdinPipe.Close()
		}()
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var deadline <-chan time.Time
	stopping := false
	// ask passes sig on to the group; asked once already, it kills it.
	ask := func(sig syscall.Signal) {
		if stopping {
			syscall.Kill(-pgid, syscall.SIGKILL)
			return
		}
		stopping = true
		syscall.Kill(-pgid, sig)
		deadline = time.After(killDelay)
	}
wait:
	for {
		select {
		case <-done:
			break wait
		case sig := <-signals:
			ask(sig.(syscall.Signal))
		case <-stop:
			stop = nil
			ask(syscall.SIGTERM)
		case <-deadline:
			syscall.Kill(-pgid, syscall.SIGKILL)
		}
	}
	stdout.Close()
	stderr.Close()

	// Wait's error is either the exit status, read here, or a failure to
	// pass on output, such as to a closed pipe, which leaves the command's
	// exit to report.
	ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return ws.ExitStatus(), nil
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	return err == nil
}
