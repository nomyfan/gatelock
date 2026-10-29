// Package redact masks secret values, and the common encodings of them, in
// a stream of output.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"strings"
	"sync"
)

// Secret is a value to mask, and the label its masks show, such as
// "prod-api/STRIPE_KEY".
type Secret struct {
	Label string
	Value []byte
}

// minFragment is the shortest base64 fragment of a value embedded in other
// data that is masked: shorter ones would mask too much unrelated output.
const minFragment = 8

// Writer masks secrets in what is written to it before passing it on. A
// secret split across writes is still masked: bytes that may begin one are
// held back until later writes, or Close, settle it. Writes are safe from
// several goroutines.
type Writer struct {
	mu       sync.Mutex
	dst      io.Writer
	patterns []pattern // longest first
	// byFirst indexes patterns by their first byte, so that most bytes of
	// output are checked against few of them.
	byFirst [256][]int
	pending []byte
}

type pattern struct {
	text []byte
	// mask replaces text when all of it is matched. label replaces a
	// beginning of text left at Close, since mask may show more of the
	// value than was output.
	mask  []byte
	label []byte
}

// NewWriter returns a Writer that writes to dst. Every secret is masked,
// however short; empty ones are ignored. A secret that is a URL-style DSN
// with a password, such as postgres://app:pw@host/db, has only the
// password masked where the DSN shows whole, as written or URL- or
// JSON-escaped; its other forms are masked whole.
func NewWriter(dst io.Writer, secrets []Secret) *Writer {
	seen := map[string]bool{}
	var patterns []pattern
	for _, s := range secrets {
		label := "[REDACTED:" + s.Label + "]"
		for _, f := range forms(string(s.Value), label) {
			if f.text == "" || seen[f.text] {
				continue
			}
			seen[f.text] = true
			patterns = append(patterns, pattern{text: []byte(f.text), mask: []byte(f.mask), label: []byte(label)})
		}
	}
	slices.SortStableFunc(patterns, func(a, b pattern) int { return len(b.text) - len(a.text) })
	w := &Writer{dst: dst, patterns: patterns}
	for i, p := range patterns {
		w.byFirst[p.text[0]] = append(w.byFirst[p.text[0]], i)
	}
	return w
}

// form is a text a secret may show as in output, and what replaces it.
type form struct {
	text string
	mask string
}

// forms returns the texts a value may show as in output: itself, its whole
// encodings, and the fragments of its base64 that stay the same wherever
// the value sits in longer encoded data. Each is replaced by label, except
// that only the passwords of a DSN are, in the forms that keep its shape.
func forms(s, label string) []form {
	if s == "" {
		return nil
	}
	spans := passwordSpans(s)
	var out []form
	// These encode each byte or rune on its own, so the encoding of s is
	// the encodings of its pieces joined, and a password can be replaced
	// alone. The spans start and end next to ASCII bytes, so no rune is
	// split.
	for _, enc := range []func(string) string{
		func(t string) string { return t },
		url.QueryEscape,
		url.PathEscape,
		func(t string) string { return jsonEscape(t, true) },
		func(t string) string { return jsonEscape(t, false) },
	} {
		mask := label
		if spans != nil {
			var b strings.Builder
			prev := 0
			for _, span := range spans {
				b.WriteString(enc(s[prev:span[0]]))
				b.WriteString(label)
				prev = span[1]
			}
			b.WriteString(enc(s[prev:]))
			mask = b.String()
		}
		out = append(out, form{enc(s), mask})
	}

	v := []byte(s)
	whole := []string{
		hex.EncodeToString(v),
		strings.ToUpper(hex.EncodeToString(v)),
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		whole = append(whole, enc.EncodeToString(v))
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for shift := range 3 {
			// With shift bytes before the value, the characters from
			// ceil(8*shift/6) up to floor(8*(shift+len)/6) carry only the
			// value's bits.
			encoded := enc.EncodeToString(append(make([]byte, shift), v...))
			start, end := (8*shift+5)/6, 8*(shift+len(v))/6
			if end-start >= minFragment {
				whole = append(whole, encoded[start:end])
			}
		}
	}
	for _, text := range whole {
		out = append(out, form{text, label})
	}
	return out
}

// jsonEscape returns s as it shows inside a JSON string.
func jsonEscape(s string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	enc.Encode(s)
	quoted := strings.TrimSuffix(b.String(), "\n")
	return quoted[1 : len(quoted)-1]
}

// Write masks p, with what earlier writes held back, and writes what is
// settled to the destination. It reports len(p) unless the destination
// fails.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, p...)
	out, rest := w.mask(w.pending, false)
	w.pending = append(w.pending[:0], rest...)
	if len(out) > 0 {
		if _, err := w.dst.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close writes what is held back. Bytes that could still begin a secret are
// masked as that secret rather than shown. It does not close the
// destination.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	out, _ := w.mask(w.pending, true)
	w.pending = nil
	if len(out) == 0 {
		return nil
	}
	_, err := w.dst.Write(out)
	return err
}

// mask replaces the patterns in b, leftmost and longest first. Unless
// final, it stops at the first byte from which the rest of b is the
// beginning of a pattern, and returns that rest to be held back.
func (w *Writer) mask(b []byte, final bool) (out, rest []byte) {
	out = make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		tail := b[i:]
		var full, partial *pattern
		for _, j := range w.byFirst[b[i]] {
			p := &w.patterns[j]
			if len(p.text) > len(tail) {
				if partial == nil && bytes.HasPrefix(p.text, tail) {
					partial = p
				}
			} else if full == nil && bytes.HasPrefix(tail, p.text) {
				full = p
			}
		}
		switch {
		case partial != nil && !final:
			return out, tail
		case full != nil:
			out = append(out, full.mask...)
			i += len(full.text)
		case partial != nil:
			return append(out, partial.label...), nil
		default:
			out = append(out, b[i])
			i++
		}
	}
	return out, nil
}
