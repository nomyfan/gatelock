package shell

import (
	"os/exec"
	"slices"
	"testing"
)

var cases = []struct {
	argv []string
	line string
}{
	{[]string{"make", "deploy"}, "make deploy"},
	{[]string{"rm", "a b"}, "rm 'a b'"},
	{[]string{"rm", "a", "b"}, "rm a b"},
	{[]string{"echo", ""}, "echo ''"},
	{[]string{"echo", "it's", "$HOME", "*", "~", "#x", "a;b"}, `echo 'it'\''s' '$HOME' '*' '~' '#x' 'a;b'`},
	{[]string{"curl", "-H", "Authorization: Bearer x", "https://example.com/a?b=c&d=é"}, `curl -H 'Authorization: Bearer x' 'https://example.com/a?b=c&d=é'`},
	{[]string{"git", "commit", "-m", "fix: it's\n\nmore\tthere"}, `git commit -m $'fix: it\'s\n\nmore\tthere'`},
	{[]string{"echo", "a\\b\x1b[31m\u202eevil\u0085"}, `echo $'a\\b\x1b[31m\xe2\x80\xaeevil\xc2\x85'`},
	{[]string{"FOO=bar", "--x=y"}, "'FOO=bar' --x=y"},
	{[]string{"go", "test", "./...", "-run=TestA", "user@host:/p,q+r%"}, "go test ./... -run=TestA user@host:/p,q+r%"},
}

func TestJoin(t *testing.T) {
	for _, c := range cases {
		if got := Join(c.argv); got != c.line {
			t.Errorf("%q: got %s, want %s", c.argv, got, c.line)
		}
	}
}

// What Join writes, bash and zsh read back as the argv it was given.
func TestReadBack(t *testing.T) {
	for _, sh := range []string{"bash", "zsh"} {
		t.Run(sh, func(t *testing.T) { readBack(t, sh) })
	}
}

func readBack(t *testing.T, sh string) {
	path, err := exec.LookPath(sh)
	if err != nil {
		t.Skip("no " + sh)
	}
	for _, c := range cases {
		// printf prints each word ending in a NUL.
		out, err := exec.Command(path, "-f", "-c", "printf '%s\\0' "+Join(c.argv)).Output()
		if err != nil {
			t.Fatalf("%q: %v", c.argv, err)
		}
		var got []string
		for len(out) > 0 {
			i := slices.Index(out, 0)
			got = append(got, string(out[:i]))
			out = out[i+1:]
		}
		if !slices.Equal(got, c.argv) {
			t.Errorf("%q: read back as %q", c.argv, got)
		}
	}
}
