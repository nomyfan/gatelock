package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gatelock/internal/ipc"
	"gatelock/internal/launch"
	"gatelock/internal/redact"
)

// Exit codes of `gatelock run` for its own failures, as env(1) and the
// shells use them.
const (
	exitGatelock = 125
	exitNotRun   = 127
)

// bundleID is the app's identifier, as mygo.json sets it.
const bundleID = "dev.callcc.gatelock"

// runCommand is `gatelock run`: it asks the app for the vault's values,
// runs the command with them in its environment, masks them in its output,
// and exits as the command does.
func runCommand(args []string) int {
	noRecordOutput := len(args) > 0 && args[0] == "--no-record-output"
	if noRecordOutput {
		args = args[1:]
	}
	// No vault's name begins with "-".
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		fmt.Fprintf(os.Stderr, "gatelock: unknown option %s\n%s\n", args[0], usage)
		return exitGatelock
	}
	if len(args) > 1 && args[1] == "--" {
		args = append(args[:1], args[2:]...)
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		return exitGatelock
	}
	name, argv := args[0], args[1:]

	fail := func(err error) int {
		fmt.Fprintf(os.Stderr, "gatelock: %v\n", err)
		return exitGatelock
	}
	dir, err := home()
	if err != nil {
		return fail(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	nc, err := ipc.Dial(socketPath(dir), startApp)
	if err != nil {
		return fail(err)
	}
	session, secrets, err := ipc.Run(nc, ipc.RunRequest{Vault: name, Argv: argv, Cwd: cwd, NoRecordOutput: noRecordOutput})
	if err != nil {
		return fail(err)
	}

	env := os.Environ()
	var masks []redact.Secret
	for _, s := range secrets {
		env = setEnv(env, s.Key, string(s.Value))
		if s.Sensitive {
			masks = append(masks, redact.Secret{Label: name + "/" + s.Key, Value: s.Value})
		}
	}
	var record io.Writer = session
	if noRecordOutput {
		record = nil
	}
	code, err := launch.Run(launch.Spec{
		Argv:   argv,
		Cwd:    cwd,
		Env:    env,
		Redact: masks,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Record: record,
	}, session.Started, session.Stop())
	if err != nil {
		session.Failed(err)
		fmt.Fprintf(os.Stderr, "gatelock: %v\n", err)
		return exitNotRun
	}
	lost := false
	select {
	case <-session.Stop():
		lost = session.Lost()
	default:
	}
	session.Exit(code)
	if lost {
		return fail(errors.New("lost the connection to Gatelock, so the command was stopped"))
	}
	return code
}

// setEnv sets key in env, replacing what it held.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := env[:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, prefix) {
			out = append(out, kv)
		}
	}
	return append(out, prefix+value)
}

// startApp starts the app in the background, without its window: the
// bundle this executable is in, else the one installed.
func startApp() error {
	args := []string{"-g"}
	if bundle := appBundle(); bundle != "" {
		args = append(args, bundle)
	} else {
		args = append(args, "-b", bundleID)
	}
	args = append(args, "--args", "--background")
	if out, err := exec.Command("open", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// appBundle returns the .app this executable is in, through any symlink to
// it, or "".
func appBundle() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return ""
	}
	for dir := filepath.Dir(exe); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if strings.HasSuffix(dir, ".app") {
			return dir
		}
	}
	return ""
}
