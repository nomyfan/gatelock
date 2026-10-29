package redact

import (
	"strings"
	"unicode"
)

// passwordParams are the query parameters, lowercased, whose values are
// passwords. Only names known to hold one are listed: a looser rule, such
// as any name ending in "password", would take showPassword=false for the
// secret and show the rest of a URL that has none.
var passwordParams = map[string]bool{
	"password":           true,
	"pwd":                true,
	"pass":               true,
	"passwd":             true,
	"sslpassword":        true,
	"truststorepassword": true,
	"keystorepassword":   true,
}

// passwordSpans returns where the passwords sit in v, as [start, end)
// byte offsets in order, if v is a URL-style DSN: the password in its
// userinfo and the values of password query parameters. It returns nil if
// v is not a DSN or holds no non-empty password; v is then masked whole.
// Each span starts and ends next to an ASCII byte or the end of v.
func passwordSpans(v string) [][2]int {
	start := authorityStart(v)
	if start < 0 || strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil
	}
	after := v[start:]
	authority := upTo(after, "/?#")
	// Parsers disagree on where a userinfo with an unescaped @ / ? or #
	// in it ends. RFC 3986 (net/url, WHATWG) takes the last @ before the
	// first / ? or #, libpq the first @ before the first /, SQLAlchemy the
	// first @ anywhere. Unless all three agree, the password may reach
	// past where one of them puts it. When they do, it holds none of
	// those, so the authority ends where RFC 3986 says.
	rfc := userinfoPassword(after, strings.LastIndexByte(authority, '@'))
	libpq := userinfoPassword(after, strings.IndexByte(upTo(after, "/"), '@'))
	sqlalchemy := userinfoPassword(after, strings.IndexByte(after, '@'))
	if rfc != libpq || rfc != sqlalchemy {
		return nil
	}
	var spans [][2]int
	if rfc != [2]int{} {
		spans = append(spans, [2]int{start + rfc[0], start + rfc[1]})
	}

	end := start + len(authority)
	rest := v[end:]
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	q := strings.IndexByte(rest, '?')
	if q < 0 {
		return spans
	}
	offset := end + q + 1
	for param := range strings.SplitSeq(rest[q+1:], "&") {
		name, value, ok := strings.Cut(param, "=")
		if ok && value != "" && passwordParams[strings.ToLower(name)] {
			valueStart := offset + len(name) + 1
			spans = append(spans, [2]int{valueStart, valueStart + len(value)})
		}
		offset += len(param) + 1
	}
	return spans
}

// userinfoPassword returns where the password sits in s, the text after a
// DSN's "//", if its userinfo ends at the @ at offset at: after the first
// colon, with no / before it. It returns the zero span if at < 0 or the
// userinfo has no non-empty password.
func userinfoPassword(s string, at int) [2]int {
	if at < 0 {
		return [2]int{}
	}
	colon := strings.IndexByte(s[:at], ':')
	if colon < 0 || colon+1 == at || strings.Contains(s[:colon], "/") {
		return [2]int{}
	}
	return [2]int{colon + 1, at}
}

// upTo returns s up to the first of chars in it.
func upTo(s, chars string) string {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return s[:i]
	}
	return s
}

// authorityStart returns the offset just past the "//" that follows v's
// schemes, of which there may be several, as in jdbc:postgresql://, or -1
// if v does not start that way.
func authorityStart(v string) int {
	i := 0
	for {
		j := i
		for j < len(v) && (isLetter(v[j]) || j > i && (isDigit(v[j]) || strings.IndexByte("+-.", v[j]) >= 0)) {
			j++
		}
		if j == i || j == len(v) || v[j] != ':' {
			return -1
		}
		if strings.HasPrefix(v[j+1:], "//") {
			return j + 3
		}
		i = j + 1
	}
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isDigit(c byte) bool { return '0' <= c && c <= '9' }
