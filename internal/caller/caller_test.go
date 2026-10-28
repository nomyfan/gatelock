package caller

import (
	"os"
	"testing"
)

func TestName(t *testing.T) {
	shell := process{path: "/bin/zsh", argv: []string{"-zsh"}}
	for _, tc := range []struct {
		name  string
		chain []process
		want  string
	}{
		{"native Claude Code", []process{shell, {path: "/Users/u/.local/share/claude/versions/2.1.306", argv: []string{"claude"}}}, ClaudeCode},
		{"Claude Code from npm", []process{shell, {path: "/opt/node/bin/node", argv: []string{"node", "/opt/node/lib/node_modules/@anthropic-ai/claude-code/cli.js"}}}, ClaudeCode},
		{"Codex", []process{shell, {path: "/Users/u/.codex/packages/releases/0.165.0/bin/codex", argv: []string{"codex", "app-server"}}}, Codex},
		{"an agent beyond a build tool", []process{{path: "/usr/bin/make", argv: []string{"make"}}, shell, {path: "/opt/bin/codex", argv: []string{"codex"}}}, Codex},
		{"a terminal", []process{shell, {path: "/usr/bin/login", argv: []string{"login"}}, {path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"}}, "Terminal"},
		{"an app's helper", []process{shell, {path: "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)"}}, "Cursor"},
		{"unreadable processes", []process{{}, shell, {path: "/usr/bin/make"}}, "make"},
		{"only shells", []process{shell}, ""},
		{"nothing", nil, ""},
	} {
		if got := name(tc.chain); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestOf reads the processes above the test, which go test is among.
func TestOf(t *testing.T) {
	if got := Of(os.Getpid()); got == "" {
		t.Fatal("no caller")
	}
	if got := Of(1); got != "" {
		t.Fatalf("launchd's caller is %q", got)
	}
}
