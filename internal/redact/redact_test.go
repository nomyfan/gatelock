package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func redactAll(t *testing.T, secrets []Secret, writes ...string) string {
	t.Helper()
	var out bytes.Buffer
	w := NewWriter(&out, secrets)
	for _, s := range writes {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestMasksValue(t *testing.T) {
	got := redactAll(t, []Secret{{"ns/TOKEN", []byte("sk_live_123")}}, "token=sk_live_123 done\n")
	if want := "token=[REDACTED:ns/TOKEN] done\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMasksValueSplitAcrossWrites(t *testing.T) {
	secrets := []Secret{{"ns/TOKEN", []byte("sk_live_123")}}
	var out bytes.Buffer
	w := NewWriter(&out, secrets)
	w.Write([]byte("token=sk_li"))
	// However long the pause, the beginning of the secret is not shown.
	if got := out.String(); got != "token=" {
		t.Fatalf("after first write got %q", got)
	}
	w.Write([]byte("ve_123 done"))
	w.Close()
	if got, want := out.String(), "token=[REDACTED:ns/TOKEN] done"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMasksByteByByte(t *testing.T) {
	secrets := []Secret{{"ns/TOKEN", []byte("hunter2hunter2")}}
	input := "a hunter2hunter2 b hunter2 c"
	got := redactAll(t, secrets, strings.Split(input, "")...)
	if want := "a [REDACTED:ns/TOKEN] b hunter2 c"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMasksEncodings(t *testing.T) {
	value := "p@ss/word+&=?<x>"
	secrets := []Secret{{"ns/PW", []byte(value)}}
	for name, form := range map[string]string{
		"base64":        base64.StdEncoding.EncodeToString([]byte(value)),
		"base64 raw":    base64.RawStdEncoding.EncodeToString([]byte(value)),
		"base64 url":    base64.URLEncoding.EncodeToString([]byte(value)),
		"hex":           hex.EncodeToString([]byte(value)),
		"hex upper":     strings.ToUpper(hex.EncodeToString([]byte(value))),
		"query escape":  url.QueryEscape(value),
		"path escape":   url.PathEscape(value),
		"json escaped":  `p@ss/word+&=?<x>`,
		"json no html":  `p@ss/word+&=?<x>`,
		"base64 inside": base64.StdEncoding.EncodeToString([]byte("Authorization: " + value + " trailing")),
	} {
		got := redactAll(t, secrets, "x "+form+" y")
		if strings.Contains(got, form) || !strings.Contains(got, "[REDACTED:ns/PW]") {
			t.Errorf("%s: %q not masked: %q", name, form, got)
		}
	}
}

func TestMasksShortValueAndItsEncodings(t *testing.T) {
	secrets := []Secret{{"ns/PIN", []byte("abc")}}
	for _, form := range []string{"abc", "YWJj", "616263"} {
		if got := redactAll(t, secrets, "<"+form+">"); got != "<[REDACTED:ns/PIN]>" {
			t.Errorf("%q: got %q", form, got)
		}
	}
}

func TestPrefersLongestMatch(t *testing.T) {
	secrets := []Secret{
		{"ns/SHORT", []byte("secret")},
		{"ns/LONG", []byte("secret-extended")},
	}
	got := redactAll(t, secrets, "secret-extended secret secret-ex")
	if want := "[REDACTED:ns/LONG] [REDACTED:ns/SHORT] [REDACTED:ns/SHORT]-ex"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCloseMasksHeldPrefix(t *testing.T) {
	got := redactAll(t, []Secret{{"ns/TOKEN", []byte("sk_live_123")}}, "token=sk_li")
	if want := "token=[REDACTED:ns/TOKEN]"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPassesUnrelatedOutputThrough(t *testing.T) {
	input := "plain output\nwith lines\n"
	if got := redactAll(t, []Secret{{"ns/TOKEN", []byte("zzzz")}}, input); got != input {
		t.Fatalf("got %q", got)
	}
	if got := redactAll(t, nil, input); got != input {
		t.Fatalf("no secrets: got %q", got)
	}
}

func TestConcurrentWrites(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, []Secret{{"ns/TOKEN", []byte("sk_live_123")}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				w.Write([]byte("sk_live_123\n"))
			}
		})
	}
	wg.Wait()
	w.Close()
	if strings.Contains(out.String(), "sk_live") {
		t.Fatal("secret leaked")
	}
	if n := strings.Count(out.String(), "[REDACTED:ns/TOKEN]\n"); n != 800 {
		t.Fatalf("got %d masks, want 800", n)
	}
}
