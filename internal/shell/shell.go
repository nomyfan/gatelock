// Package shell writes a command line as a shell would read it back, for
// showing the user what runs.
package shell

import (
	"fmt"
	"strings"
	"unicode"
)

// Join returns argv as one line that bash or zsh reads back as argv.
func Join(argv []string) string {
	var b strings.Builder
	for i, arg := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		// A first word with = in it would read as setting a variable.
		if i == 0 && strings.Contains(arg, "=") && strings.IndexFunc(arg, special) < 0 {
			b.WriteString("'" + arg + "'")
			continue
		}
		b.WriteString(Quote(arg))
	}
	return b.String()
}

// Quote returns arg as one word that bash or zsh reads back as arg: as it
// is if nothing in it is special, nor does it begin with = (which zsh
// reads as a command's path), else in single quotes, or, if it holds
// control or format characters, in $'...' with those escaped, so that it
// stays on one line and shows each character there is.
func Quote(arg string) string {
	switch {
	case arg == "":
		return "''"
	case strings.IndexFunc(arg, special) < 0 && arg[0] != '=':
		return arg
	case strings.IndexFunc(arg, hidden) < 0:
		return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	var b strings.Builder
	b.WriteString("$'")
	for _, r := range arg {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		case !hidden(r):
			b.WriteRune(r)
		default:
			// Byte by byte, as the bash of macOS, 3.2, reads no \u.
			for _, c := range []byte(string(r)) {
				fmt.Fprintf(&b, `\x%02x`, c)
			}
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// special reports whether r makes a word need quotes.
func special(r rune) bool {
	return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("_@%+=:,./-", r))
}

// hidden reports whether r is a control or format character, which would
// break the line, or not show, or change how the rest shows.
func hidden(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}
