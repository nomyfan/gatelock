// Package ipc is how `gatelock run` asks the app for a namespace's values
// and reports the command it runs.
//
// Each connection carries one run, as lines of JSON. The CLI sends a run
// request; the app answers with the values, once the user authorizes it,
// or an error. The CLI then reports the command starting, its masked
// output, and its exit; the app may ask it to stop. If the connection
// breaks, each side stops the command: the CLI because the app can no
// longer see it, the app because the CLI is gone.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"gatelock/internal/history"
	"gatelock/internal/vault"
)

const (
	// maxChunk is the most output one frame carries.
	maxChunk = 64 << 10
	// maxFrame bounds a frame: a chunk in base64, or a run's values.
	maxFrame = 16 << 20
)

// frame is a message either way.
type frame struct {
	Type string `json:"type"`

	// run
	Namespace string   `json:"namespace,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	// granted
	RunID string         `json:"run_id,omitempty"`
	Env   []vault.Secret `json:"env,omitempty"`
	// error
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	// started
	PGID int `json:"pgid,omitempty"`
	// output
	Data []byte `json:"data,omitempty"`
	// exit
	Code int `json:"code,omitempty"`
}

// The kinds of error the app answers a run request with.
const (
	errNotFound = "not_found"
	errDenied   = "denied"
	errInvalid  = "invalid"
	errStopped  = "stopped"
	errInternal = "internal"
)

// conn reads and writes frames; writes are safe from several goroutines.
type conn struct {
	c  net.Conn
	r  *bufio.Scanner
	mu sync.Mutex
}

func newConn(c net.Conn) *conn {
	r := bufio.NewScanner(c)
	r.Buffer(make([]byte, 64<<10), maxFrame)
	return &conn{c: c, r: r}
}

func (c *conn) read() (frame, error) {
	if !c.r.Scan() {
		if err := c.r.Err(); err != nil {
			return frame{}, err
		}
		return frame{}, net.ErrClosed
	}
	var f frame
	err := json.Unmarshal(c.r.Bytes(), &f)
	return f, err
}

func (c *conn) write(f frame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.c.Write(append(data, '\n'))
	return err
}

// Listen listens on the socket at path, replacing one left by an app that
// did not quit cleanly. Only the user can connect to it.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve handles the runs asked for on l until it is closed. It is the
// boundary where requests are checked: the peer must be this user, the
// namespace must exist, the command must not be empty, and the directory
// must be an absolute path that exists.
func Serve(l net.Listener, v *vault.Vault, h *history.Store) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go serve(c, v, h)
	}
}

func serve(nc net.Conn, v *vault.Vault, h *history.Store) {
	defer nc.Close()
	if !sameUser(nc) {
		return
	}
	c := newConn(nc)
	req, err := c.read()
	if err != nil || req.Type != "run" {
		return
	}
	if msg := checkRequest(req, v); msg != "" {
		kind := errInvalid
		if _, err := v.Namespace(req.Namespace); errors.Is(err, vault.ErrNotFound) {
			kind = errNotFound
		}
		c.write(frame{Type: "error", Error: kind, Message: msg})
		return
	}

	// The CLI stops the command once the run is granted. Before, stopping
	// dismisses the question, and the run ends without the command.
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	granted, stopped := false, false
	rec, err := h.Begin(req.Namespace, req.Argv, req.Cwd, func() {
		mu.Lock()
		defer mu.Unlock()
		if granted {
			c.write(frame{Type: "stop"})
			return
		}
		stopped = true
		cancel()
	})
	if err != nil {
		cancel()
		c.write(frame{Type: "error", Error: errInternal, Message: err.Error()})
		return
	}
	// Frames are read on as the user is asked, so that the question is
	// dismissed if the CLI goes away.
	frames := make(chan frame)
	go func() {
		defer cancel()
		defer close(frames)
		for {
			f, err := c.read()
			if err != nil {
				return
			}
			frames <- f
		}
	}()

	reason := fmt.Sprintf("unlock %s to run %s", req.Namespace, strings.Join(req.Argv, " "))
	secrets, err := v.Resolve(ctx, req.Namespace, reason)
	mu.Lock()
	switch {
	case stopped:
		mu.Unlock()
		rec.End(history.Stopped)
		c.write(frame{Type: "error", Error: errStopped, Message: "stopped in Gatelock before it was authorized"})
		return
	case ctx.Err() != nil:
		mu.Unlock()
		rec.End(history.Lost)
		return
	case errors.Is(err, vault.ErrDenied):
		mu.Unlock()
		rec.End(history.Denied)
		c.write(frame{Type: "error", Error: errDenied, Message: "authorization denied"})
		return
	case err != nil:
		mu.Unlock()
		rec.Write([]byte("gatelock: " + err.Error() + "\n"))
		rec.End(history.Failed)
		c.write(frame{Type: "error", Error: errInternal, Message: err.Error()})
		return
	}
	rec.Authorized()
	if secrets == nil {
		secrets = []vault.Secret{}
	}
	// Granted under mu, so that a stop asked meanwhile follows it.
	granted = true
	c.write(frame{Type: "granted", RunID: rec.ID(), Env: secrets})
	mu.Unlock()

	pgid := 0
	for f := range frames {
		switch f.Type {
		case "started":
			pgid = f.PGID
			rec.Started(pgid)
		case "output":
			rec.Write(f.Data)
		case "failed":
			rec.Write([]byte("gatelock: " + f.Message + "\n"))
			rec.End(history.Failed)
			return
		case "exit":
			rec.Exited(f.Code)
			return
		}
	}
	// The CLI went away without the command's exit.
	if pgid > 0 {
		go killGroup(pgid)
	}
	rec.End(history.Lost)
}

func checkRequest(req frame, v *vault.Vault) string {
	if _, err := v.Namespace(req.Namespace); err != nil {
		var names []string
		for _, ns := range v.Namespaces() {
			names = append(names, ns.Name)
		}
		return fmt.Sprintf("no namespace %q (namespaces: %s)", req.Namespace, strings.Join(names, ", "))
	}
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return "no command"
	}
	if !filepath.IsAbs(req.Cwd) {
		return fmt.Sprintf("working directory %q is not absolute", req.Cwd)
	}
	if info, err := os.Stat(req.Cwd); err != nil || !info.IsDir() {
		return fmt.Sprintf("working directory %q does not exist", req.Cwd)
	}
	return ""
}

// killGroup stops a process group no one else will: politely, then not.
func killGroup(pgid int) {
	if syscall.Kill(-pgid, syscall.SIGTERM) != nil {
		return
	}
	time.Sleep(5 * time.Second)
	syscall.Kill(-pgid, syscall.SIGKILL)
}

func sameUser(c net.Conn) bool {
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Xucred
	raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	return err == nil && int(cred.Uid) == os.Getuid()
}

// RunRequest is what `gatelock run` asks for.
type RunRequest struct {
	Namespace string
	Argv      []string
	Cwd       string
}

// Session is a run the app authorized, as the CLI reports it.
type Session struct {
	c      *conn
	frames chan frame // to send, in order
	sent   chan struct{}
	stop   chan struct{}
	lost   bool // set before stop closes

	mu      sync.Mutex
	dropped bool
}

// Dial connects to the app at the socket, calling start to start it if
// nothing listens there, and waiting for it up to 10s.
func Dial(socketPath string, start func() error) (net.Conn, error) {
	c, err := net.Dial("unix", socketPath)
	if err == nil {
		return c, nil
	}
	if err := start(); err != nil {
		return nil, fmt.Errorf("start Gatelock: %w", err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if c, err = net.Dial("unix", socketPath); err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("Gatelock did not start: %w", err)
}

// Run asks the app over nc to run a command, and waits for the user to
// authorize it. It returns the namespace's values, or an error wrapping
// vault.ErrNotFound, vault.ErrDenied, or another with the app's message.
func Run(nc net.Conn, req RunRequest) (*Session, []vault.Secret, error) {
	c := newConn(nc)
	if err := c.write(frame{Type: "run", Namespace: req.Namespace, Argv: req.Argv, Cwd: req.Cwd}); err != nil {
		nc.Close()
		return nil, nil, err
	}
	answer, err := c.read()
	if err != nil {
		nc.Close()
		return nil, nil, fmt.Errorf("Gatelock closed the connection: %w", err)
	}
	if answer.Type != "granted" {
		nc.Close()
		switch answer.Error {
		case errNotFound:
			return nil, nil, fmt.Errorf("%w: %s", vault.ErrNotFound, answer.Message)
		case errDenied:
			return nil, nil, vault.ErrDenied
		}
		return nil, nil, errors.New(answer.Message)
	}

	s := &Session{
		c:      c,
		frames: make(chan frame, 256),
		sent:   make(chan struct{}),
		stop:   make(chan struct{}),
	}
	go s.send()
	go func() {
		for {
			f, err := c.read()
			if err != nil {
				s.lost = true
				close(s.stop)
				return
			}
			if f.Type == "stop" {
				close(s.stop)
				// The app may still see the command exit; reading on would
				// only meet the connection closing.
				return
			}
		}
	}()
	return s, answer.Env, nil
}

func (s *Session) send() {
	defer close(s.sent)
	for f := range s.frames {
		s.mu.Lock()
		dropped := s.dropped
		s.dropped = false
		s.mu.Unlock()
		if dropped {
			s.c.write(frame{Type: "output", Data: []byte("\n[gatelock: output dropped]\n")})
		}
		s.c.write(f)
	}
}

// Started reports the command's process group.
func (s *Session) Started(pgid int) { s.frames <- frame{Type: "started", PGID: pgid} }

// Write reports masked output. It never blocks: output the app is too slow
// to take is dropped, and the record says so.
func (s *Session) Write(p []byte) (int, error) {
	for rest := p; len(rest) > 0; {
		chunk := rest[:min(len(rest), maxChunk)]
		rest = rest[len(chunk):]
		select {
		case s.frames <- frame{Type: "output", Data: append([]byte(nil), chunk...)}:
		default:
			s.mu.Lock()
			s.dropped = true
			s.mu.Unlock()
		}
	}
	return len(p), nil
}

// Stop is closed when the app asks the command to stop, or the connection
// to it breaks.
func (s *Session) Stop() <-chan struct{} { return s.stop }

// Lost reports whether Stop closed because the connection broke. It is
// valid once Stop is closed.
func (s *Session) Lost() bool { return s.lost }

// Exit reports the command's exit code, after the output, and closes the
// session.
func (s *Session) Exit(code int) { s.finish(frame{Type: "exit", Code: code}) }

// Failed reports that the command could not be started, and closes the
// session.
func (s *Session) Failed(err error) { s.finish(frame{Type: "failed", Message: err.Error()}) }

func (s *Session) finish(f frame) {
	s.frames <- f
	close(s.frames)
	<-s.sent
	s.c.c.Close()
}
