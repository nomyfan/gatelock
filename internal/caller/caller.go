// Package caller tells which program ran `gatelock run`, from the
// processes above it: a coding agent if one is among them, else the first
// that is not a shell. It reads what the processes say of themselves,
// which a program can make up, so it is a hint for the user, not a check.
package caller

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// The agents told apart by name.
const (
	ClaudeCode = "Claude Code"
	Codex      = "Codex"
)

// process is what is read of one process.
type process struct {
	path string   // the executable
	argv []string // nil if it could not be read
}

// Of returns the name of the program that ran the process pid, or "" if
// none is known. It is to be called while pid is alive, as it reads the
// processes above it then.
func Of(pid int) string {
	var chain []process
	// Up to launchd, bounded in case the processes change meanwhile.
	for range 64 {
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil {
			break
		}
		pid = int(kp.Eproc.Ppid)
		if pid <= 1 {
			break
		}
		chain = append(chain, read(pid))
	}
	return name(chain)
}

// read reads a process's executable and arguments from kern.procargs2:
// argc, the executable's path, then the arguments, each ending with NUL.
func read(pid int) process {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(buf) < 4 {
		return process{}
	}
	argc := int(binary.LittleEndian.Uint32(buf))
	rest := buf[4:]
	path, rest, _ := bytes.Cut(rest, []byte{0})
	rest = bytes.TrimLeft(rest, "\x00")
	p := process{path: string(path)}
	for range argc {
		arg, after, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			break
		}
		p.argv = append(p.argv, string(arg))
		rest = after
	}
	return p
}

// name names the program in chain, which runs from the parent up.
func name(chain []process) string {
	for _, p := range chain {
		if agent := agentOf(p); agent != "" {
			return agent
		}
	}
	for _, p := range chain {
		if p.path == "" || passThrough[filepath.Base(p.path)] {
			continue
		}
		return appName(p.path)
	}
	return ""
}

func agentOf(p process) string {
	arg0 := ""
	if len(p.argv) > 0 {
		arg0 = filepath.Base(p.argv[0])
	}
	exe := filepath.Base(p.path)
	switch {
	// The native install runs as .../claude/versions/<version>.
	case arg0 == "claude" || exe == "claude" || strings.Contains(p.path, "/claude/versions/"):
		return ClaudeCode
	// Installed with npm, it runs under node.
	case slices.ContainsFunc(p.argv, func(a string) bool { return strings.Contains(a, "/@anthropic-ai/claude-code/") }):
		return ClaudeCode
	case arg0 == "codex" || exe == "codex":
		return Codex
	}
	return ""
}

// passThrough are the programs that only run others: the one that ran
// them says more.
var passThrough = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true,
	"ksh": true, "tcsh": true, "csh": true, "nu": true,
	"login": true, "env": true, "sudo": true, "timeout": true, "xargs": true,
}

// appName names an executable by the outermost app it is in, so that a
// helper of an app reads as the app, else by its file name.
func appName(path string) string {
	if i := strings.Index(path, ".app/"); i >= 0 {
		return filepath.Base(path[:i])
	}
	return filepath.Base(path)
}
