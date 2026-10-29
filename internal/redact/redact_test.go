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
	got := redactAll(t, []Secret{{"dev/TOKEN", []byte("sk_live_123")}}, "token=sk_live_123 done\n")
	if want := "token=[REDACTED:dev/TOKEN] done\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMasksValueSplitAcrossWrites(t *testing.T) {
	secrets := []Secret{{"dev/TOKEN", []byte("sk_live_123")}}
	var out bytes.Buffer
	w := NewWriter(&out, secrets)
	w.Write([]byte("token=sk_li"))
	// However long the pause, the beginning of the secret is not shown.
	if got := out.String(); got != "token=" {
		t.Fatalf("after first write got %q", got)
	}
	w.Write([]byte("ve_123 done"))
	w.Close()
	if got, want := out.String(), "token=[REDACTED:dev/TOKEN] done"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMasksByteByByte(t *testing.T) {
	secrets := []Secret{{"dev/TOKEN", []byte("hunter2hunter2")}}
	input := "a hunter2hunter2 b hunter2 c"
	got := redactAll(t, secrets, strings.Split(input, "")...)
	if want := "a [REDACTED:dev/TOKEN] b hunter2 c"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMasksEncodings(t *testing.T) {
	value := "p@ss/word+&=?<x>"
	secrets := []Secret{{"dev/PW", []byte(value)}}
	for name, form := range map[string]string{
		"base64":        base64.StdEncoding.EncodeToString([]byte(value)),
		"base64 raw":    base64.RawStdEncoding.EncodeToString([]byte(value)),
		"base64 url":    base64.URLEncoding.EncodeToString([]byte(value)),
		"hex":           hex.EncodeToString([]byte(value)),
		"hex upper":     strings.ToUpper(hex.EncodeToString([]byte(value))),
		"query escape":  url.QueryEscape(value),
		"path escape":   url.PathEscape(value),
		"json escaped":  `p@ss/word+\u0026=?\u003cx\u003e`,
		"json no html":  `p@ss/word+&=?<x>`,
		"base64 inside": base64.StdEncoding.EncodeToString([]byte("Authorization: " + value + " trailing")),
	} {
		got := redactAll(t, secrets, "x "+form+" y")
		if strings.Contains(got, form) || !strings.Contains(got, "[REDACTED:dev/PW]") {
			t.Errorf("%s: %q not masked: %q", name, form, got)
		}
	}
}

func TestMasksShortValueAndItsEncodings(t *testing.T) {
	secrets := []Secret{{"dev/PIN", []byte("abc")}}
	for _, form := range []string{"abc", "YWJj", "616263"} {
		if got := redactAll(t, secrets, "<"+form+">"); got != "<[REDACTED:dev/PIN]>" {
			t.Errorf("%q: got %q", form, got)
		}
	}
}

func TestPrefersLongestMatch(t *testing.T) {
	secrets := []Secret{
		{"dev/SHORT", []byte("secret")},
		{"dev/LONG", []byte("secret-extended")},
	}
	got := redactAll(t, secrets, "secret-extended secret secret-ex")
	if want := "[REDACTED:dev/LONG] [REDACTED:dev/SHORT] [REDACTED:dev/SHORT]-ex"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCloseMasksHeldPrefix(t *testing.T) {
	got := redactAll(t, []Secret{{"dev/TOKEN", []byte("sk_live_123")}}, "token=sk_li")
	if want := "token=[REDACTED:dev/TOKEN]"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMasksOnlyDSNPassword(t *testing.T) {
	for _, tc := range []struct{ value, output, want string }{
		{
			"postgres://app:s3cret@db.internal:5432/orders",
			"connecting to postgres://app:s3cret@db.internal:5432/orders\n",
			"connecting to postgres://app:[REDACTED:dev/DB]@db.internal:5432/orders\n",
		},
		{
			"postgresql+asyncpg://app:s3cret@db.internal/orders",
			"url=postgresql+asyncpg://app:s3cret@db.internal/orders",
			"url=postgresql+asyncpg://app:[REDACTED:dev/DB]@db.internal/orders",
		},
		{
			"jdbc:postgresql://db.internal/orders?user=app&password=s3cret",
			"jdbc:postgresql://db.internal/orders?user=app&password=s3cret ok",
			"jdbc:postgresql://db.internal/orders?user=app&password=[REDACTED:dev/DB] ok",
		},
		{
			"postgres://postgres:postgres@localhost/postgres",
			"postgres://postgres:postgres@localhost/postgres postgres\n",
			"postgres://postgres:[REDACTED:dev/DB]@localhost/postgres postgres\n",
		},
		{
			"postgres://app:p%7Ess@db/x",
			"postgres://app:p%7Ess@db/x",
			"postgres://app:[REDACTED:dev/DB]@db/x",
		},
		{
			"postgres://app:one@db/x?sslpassword=two",
			"postgres://app:one@db/x?sslpassword=two",
			"postgres://app:[REDACTED:dev/DB]@db/x?sslpassword=[REDACTED:dev/DB]",
		},
		{
			"postgres://app:s3cret@db/x?options=a@b",
			"postgres://app:s3cret@db/x?options=a@b\n",
			"postgres://app:[REDACTED:dev/DB]@db/x?options=a@b\n",
		},
		{
			"postgres://app:pa/ss@db/x?password=other",
			"postgres://app:pa/ss@db/x?password=other",
			"[REDACTED:dev/DB]",
		},
		{
			"https://hooks.slack.com/services/T0/B0/XXXX",
			"POST https://hooks.slack.com/services/T0/B0/XXXX",
			"POST [REDACTED:dev/DB]",
		},
	} {
		got := redactAll(t, []Secret{{"dev/DB", []byte(tc.value)}}, tc.output)
		if got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.value, got, tc.want)
		}
	}
}

func TestMasksDSNPasswordInEscapedForms(t *testing.T) {
	value := "jdbc:mysql://app:p+s<s>@db/x?user=a&b<c>"
	secrets := []Secret{{"dev/DB", []byte(value)}}
	for _, tc := range []struct{ name, output, want string }{
		{"query escape", url.QueryEscape(value), "jdbc%3Amysql%3A%2F%2Fapp%3A[REDACTED:dev/DB]%40db%2Fx%3Fuser%3Da%26b%3Cc%3E"},
		{"path escape", url.PathEscape(value), "jdbc:mysql:%2F%2Fapp:[REDACTED:dev/DB]@db%2Fx%3Fuser=a&b%3Cc%3E"},
		{"json escaped", `jdbc:mysql://app:p+s\u003cs\u003e@db/x?user=a\u0026b\u003cc\u003e`, `jdbc:mysql://app:[REDACTED:dev/DB]@db/x?user=a\u0026b\u003cc\u003e`},
		{"base64", base64.StdEncoding.EncodeToString([]byte(value)), "[REDACTED:dev/DB]"},
		{"hex", hex.EncodeToString([]byte(value)), "[REDACTED:dev/DB]"},
		{"base64 inside", base64.StdEncoding.EncodeToString([]byte("DATABASE_URL=" + value + "\n")), ""},
	} {
		got := redactAll(t, secrets, tc.output)
		if tc.want != "" && got != tc.want || !strings.Contains(got, "[REDACTED:dev/DB]") {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestMasksDSNPasswordByteByByte(t *testing.T) {
	secrets := []Secret{{"dev/DB", []byte("postgres://app:s3cret@db/x")}}
	input := "a postgres://app:s3cret@db/x b postgres://app:s3 c\n"
	got := redactAll(t, secrets, strings.Split(input, "")...)
	if want := "a postgres://app:[REDACTED:dev/DB]@db/x b postgres://app:s3 c\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCloseMasksHeldDSNPrefixWhole(t *testing.T) {
	// What replaces a whole DSN shows its host and database; a beginning
	// of it left at Close must not show the rest, which was never output.
	got := redactAll(t, []Secret{{"dev/DB", []byte("postgres://app:s3cret@db.internal/orders")}}, "url=postgres://app:s3")
	if want := "url=[REDACTED:dev/DB]"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPassesUnrelatedOutputThrough(t *testing.T) {
	input := "plain output\nwith lines\n"
	if got := redactAll(t, []Secret{{"dev/TOKEN", []byte("zzzz")}}, input); got != input {
		t.Fatalf("got %q", got)
	}
	if got := redactAll(t, nil, input); got != input {
		t.Fatalf("no secrets: got %q", got)
	}
}

func TestConcurrentWrites(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out, []Secret{{"dev/TOKEN", []byte("sk_live_123")}})
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
	if n := strings.Count(out.String(), "[REDACTED:dev/TOKEN]\n"); n != 800 {
		t.Fatalf("got %d masks, want 800", n)
	}
}
