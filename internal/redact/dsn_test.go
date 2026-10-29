package redact

import (
	"slices"
	"testing"
)

func TestPasswordSpans(t *testing.T) {
	for _, tc := range []struct {
		value     string
		passwords []string // nil when the value is masked whole
	}{
		{"postgres://app:s3cret@db.internal:5432/orders", []string{"s3cret"}},
		{"postgresql+asyncpg://app:s3cret@db.internal/orders", []string{"s3cret"}},
		{"jdbc:postgresql://db.internal/orders?user=app&password=s3cret", []string{"s3cret"}},
		{"jdbc:mysql://app:s3cret@db.internal/orders", []string{"s3cret"}},
		{"redis://:s3cret@localhost:6379/0", []string{"s3cret"}},
		{"postgres://app:s3cret@[::1]:5432/db", []string{"s3cret"}},
		{"mongodb://app:s3cret@h1:27017,h2:27017/db?replicaSet=rs0", []string{"s3cret"}},
		{"postgres://postgres:postgres@localhost/postgres", []string{"postgres"}},
		{"postgres://app:p%40ss@db/x", []string{"p%40ss"}},
		{"postgres://app:p%ss@db/x", []string{"p%ss"}},
		{"postgres://app:p:ss@db/x", []string{"p:ss"}},
		{"postgres://app:one@db/x?sslmode=require&sslpassword=two#frag", []string{"one", "two"}},
		{"jdbc:sqlserver://db/x?PWD=s3cret", []string{"s3cret"}},
		{"jdbc:mysql://db/x?trustStorePassword=s3cret&user=app", []string{"s3cret"}},
		{"postgres://app:s3cret@db/x?options=a@b", []string{"s3cret"}},
		{"jdbc:postgresql://db/x?user=a@corp&password=s3cret", []string{"s3cret"}},
		// RFC 3986, libpq and SQLAlchemy all take p for the password here,
		// so it is all of it that a driver would use.
		{"postgres://app:p@ss/w@db/x", []string{"p"}},

		// Where RFC 3986, libpq and SQLAlchemy put the password differ, so
		// the value is masked whole.
		{"postgres://app:p@ss@db/x", nil},
		{"postgres://app:pa/ss@db/x", nil},
		{"postgres://app:pa?ss@db/x", nil},
		{"postgres://app:pa#ss@db/x", nil},
		{"postgres://app:pa/ss@db/x?password=other", nil},
		{"postgres://db:5432?user=a@corp&password=s3cret", nil},
		{"postgres://app:s3cret@db/x ", nil},
		{"postgres://app:s3cret@db/x\n", nil},
		{"postgres://app:s3 cret@db/x", nil},
		{"postgres://app:@db/x", nil},
		{"postgres://app@db/x", nil},
		{"postgres://db/x?password=&user=app", nil},
		{"postgres://db/x#?password=s3cret", nil},
		{"https://example.test/path?showPassword=false&token=secret", nil},
		{"https://hooks.slack.com/services/T0/B0/XXXX", nil},
		{"redis://localhost:6379", nil},
		{" postgres://app:s3cret@db/x", nil},
		{"app:s3cret@db/x", nil},
		{"mailto:app@example.test", nil},
		{"sk_live_123", nil},
		{"", nil},
	} {
		var got []string
		for _, span := range passwordSpans(tc.value) {
			got = append(got, tc.value[span[0]:span[1]])
		}
		if !slices.Equal(got, tc.passwords) {
			t.Errorf("%q: got %q, want %q", tc.value, got, tc.passwords)
		}
	}
}
