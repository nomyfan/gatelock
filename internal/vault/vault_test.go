package vault

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() { workFactor = 10 }

// fakeAuth answers as the user would: confirming unless deny is set, and
// giving the passphrases queued, then pass.
type fakeAuth struct {
	mu       sync.Mutex
	deny     bool
	pass     string
	queue    []string
	retries  []bool
	confirms atomic.Int32
	asks     atomic.Int32
	// hold, if not nil, keeps ConfirmUser waiting until it is closed.
	hold chan struct{}
}

func (a *fakeAuth) ConfirmUser(ctx context.Context, reason string) error {
	a.confirms.Add(1)
	if a.hold != nil {
		select {
		case <-a.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if a.deny {
		return ErrDenied
	}
	return nil
}

func (a *fakeAuth) AskPassphrase(ctx context.Context, ns, reason string, retry bool) ([]byte, error) {
	a.asks.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retries = append(a.retries, retry)
	if a.deny {
		return nil, ErrDenied
	}
	if len(a.queue) > 0 {
		p := a.queue[0]
		a.queue = a.queue[1:]
		return []byte(p), nil
	}
	return []byte(a.pass), nil
}

type fakeKeychain struct {
	mu      sync.Mutex
	items   map[string]string
	failSet bool
}

func (k *fakeKeychain) Get(account string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.items[account]
	if !ok {
		return nil, errors.New("not found")
	}
	return []byte(v), nil
}

func (k *fakeKeychain) Set(account string, secret []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failSet {
		return errors.New("keychain unavailable")
	}
	k.items[account] = string(secret)
	return nil
}

func (k *fakeKeychain) Delete(account string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.items, account)
	return nil
}

// only returns the single item a keychain holds.
func (k *fakeKeychain) only(t *testing.T) (account, secret string) {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.items) != 1 {
		t.Fatalf("keychain holds %d items", len(k.items))
	}
	for a, s := range k.items {
		return a, s
	}
	return
}

func TestCreateSetResolveWithKeychain(t *testing.T) {
	dir := t.TempDir()
	kc := &fakeKeychain{items: map[string]string{}}
	auth := &fakeAuth{}
	v, err := Open(dir, kc, auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create("prod-api", []byte("correct horse"), true, Policy{Mode: Every}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetEnv("prod-api", "TOKEN", []byte("sk_live_123")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetEnv("prod-api", "PORT", []byte("5432")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSensitive("prod-api", "PORT", false); err != nil {
		t.Fatal(err)
	}

	secrets, err := v.Resolve(context.Background(), "prod-api", "test")
	if err != nil {
		t.Fatal(err)
	}
	want := []Secret{{"PORT", []byte("5432"), false}, {"TOKEN", []byte("sk_live_123"), true}}
	if len(secrets) != 2 || secrets[0].Key != want[0].Key || !bytes.Equal(secrets[1].Value, want[1].Value) || secrets[0].Sensitive || !secrets[1].Sensitive {
		t.Fatalf("got %+v", secrets)
	}
	if auth.confirms.Load() != 1 || auth.asks.Load() != 0 {
		t.Fatalf("confirms %d, asks %d", auth.confirms.Load(), auth.asks.Load())
	}

	// Nothing on disk shows the value or the passphrase.
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(path)
		if bytes.Contains(data, []byte("sk_live_123")) || bytes.Contains(data, []byte("correct horse")) {
			t.Errorf("%s holds a secret in the clear", path)
		}
		return nil
	})

	// Reopened, the vault has the same namespace and values.
	v2, err := Open(dir, kc, auth)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := v2.Namespace("prod-api")
	if err != nil || len(ns.Envs) != 2 || !ns.Keychain {
		t.Fatalf("reopened: %+v, %v", ns, err)
	}
	if secrets, err := v2.Resolve(context.Background(), "prod-api", "test"); err != nil || string(secrets[1].Value) != "sk_live_123" {
		t.Fatalf("reopened resolve: %+v, %v", secrets, err)
	}
}

func TestKeysDifferingInCaseAreDistinct(t *testing.T) {
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, &fakeAuth{})
	v.Create("ns", []byte("pw"), true, Policy{Mode: Every})
	v.SetEnv("ns", "token", []byte("lower"))
	v.SetEnv("ns", "TOKEN", []byte("upper"))
	secrets, err := v.Resolve(context.Background(), "ns", "test")
	if err != nil || len(secrets) != 2 || string(secrets[0].Value) != "upper" || string(secrets[1].Value) != "lower" {
		t.Fatalf("got %+v, %v", secrets, err)
	}
}

func TestEveryAsksEachRequestEvenConcurrent(t *testing.T) {
	auth := &fakeAuth{hold: make(chan struct{})}
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, auth)
	v.Create("ns", []byte("pw"), true, Policy{Mode: Every})

	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			if _, err := v.Resolve(context.Background(), "ns", "test"); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	// One question at a time.
	if n := auth.confirms.Load(); n != 1 {
		t.Fatalf("%d questions at once", n)
	}
	close(auth.hold)
	wg.Wait()
	if n := auth.confirms.Load(); n != 3 {
		t.Fatalf("confirms %d, want 3", n)
	}
}

func TestTTLSharesOneAuthorizationUntilItExpires(t *testing.T) {
	auth := &fakeAuth{hold: make(chan struct{})}
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, auth)
	v.Create("ns", []byte("pw"), true, Policy{Mode: TTL, TTL: time.Second})

	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			if _, err := v.Resolve(context.Background(), "ns", "test"); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	close(auth.hold)
	wg.Wait()
	if n := auth.confirms.Load(); n != 1 {
		t.Fatalf("confirms %d, want 1", n)
	}
	time.Sleep(1100 * time.Millisecond)
	v.Resolve(context.Background(), "ns", "test")
	if n := auth.confirms.Load(); n != 2 {
		t.Fatalf("after expiry confirms %d, want 2", n)
	}
}

func TestSessionLastsUntilLocked(t *testing.T) {
	auth := &fakeAuth{}
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, auth)
	v.Create("ns", []byte("pw"), true, Policy{Mode: Session})
	v.Resolve(context.Background(), "ns", "test")
	v.Resolve(context.Background(), "ns", "test")
	if n := auth.confirms.Load(); n != 1 {
		t.Fatalf("confirms %d, want 1", n)
	}
	v.LockAll()
	v.Resolve(context.Background(), "ns", "test")
	if n := auth.confirms.Load(); n != 2 {
		t.Fatalf("after lock confirms %d, want 2", n)
	}
	// Changing the policy locks too.
	v.SetPolicy("ns", Policy{Mode: Session})
	v.Resolve(context.Background(), "ns", "test")
	if n := auth.confirms.Load(); n != 3 {
		t.Fatalf("after policy change confirms %d, want 3", n)
	}
}

func TestWithoutKeychainAsksPassphraseUntilRight(t *testing.T) {
	kc := &fakeKeychain{items: map[string]string{}}
	auth := &fakeAuth{queue: []string{"wrong", "pw"}}
	v, _ := Open(t.TempDir(), kc, auth)
	v.Create("ns", []byte("pw"), false, Policy{Mode: Every})
	if len(kc.items) != 0 {
		t.Fatal("passphrase in keychain")
	}
	if _, err := v.Resolve(context.Background(), "ns", "test"); err != nil {
		t.Fatal(err)
	}
	if auth.confirms.Load() != 0 || len(auth.retries) != 2 || auth.retries[0] || !auth.retries[1] {
		t.Fatalf("confirms %d, retries %v", auth.confirms.Load(), auth.retries)
	}
}

func TestDenied(t *testing.T) {
	auth := &fakeAuth{deny: true}
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, auth)
	v.Create("ns", []byte("pw"), true, Policy{Mode: Session})
	if _, err := v.Resolve(context.Background(), "ns", "test"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if _, err := v.Resolve(context.Background(), "nope", "test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestCanceledWhileWaitingForAnotherQuestion(t *testing.T) {
	auth := &fakeAuth{hold: make(chan struct{})}
	defer close(auth.hold)
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, auth)
	v.Create("a", []byte("pw"), true, Policy{Mode: Every})
	v.Create("b", []byte("pw"), true, Policy{Mode: Every})
	go v.Resolve(context.Background(), "a", "test")
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := v.Resolve(ctx, "b", "test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestMissingOrStaleKeychainItemIsAskedForAndRepaired(t *testing.T) {
	for name, spoil := range map[string]func(kc *fakeKeychain, account string){
		"missing": func(kc *fakeKeychain, account string) { delete(kc.items, account) },
		"stale":   func(kc *fakeKeychain, account string) { kc.items[account] = "old" },
	} {
		kc := &fakeKeychain{items: map[string]string{}}
		auth := &fakeAuth{pass: "pw"}
		v, _ := Open(t.TempDir(), kc, auth)
		v.Create("ns", []byte("pw"), true, Policy{Mode: Every})
		account, _ := kc.only(t)
		spoil(kc, account)

		if _, err := v.Resolve(context.Background(), "ns", "test"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if auth.asks.Load() != 1 {
			t.Fatalf("%s: asks %d", name, auth.asks.Load())
		}
		if _, secret := kc.only(t); secret != "pw" {
			t.Fatalf("%s: keychain holds %q", name, secret)
		}
		v.Resolve(context.Background(), "ns", "test")
		if auth.asks.Load() != 1 {
			t.Fatalf("%s: asked again after repair", name)
		}
	}
}

func TestChangePassphraseWithKeychainFailingRecovers(t *testing.T) {
	kc := &fakeKeychain{items: map[string]string{}}
	auth := &fakeAuth{pass: "new"}
	v, _ := Open(t.TempDir(), kc, auth)
	v.Create("ns", []byte("old"), true, Policy{Mode: Every})
	v.SetEnv("ns", "TOKEN", []byte("value"))

	kc.failSet = true
	if err := v.ChangePassphrase(context.Background(), "ns", []byte("new")); !errors.Is(err, ErrKeychainStale) {
		t.Fatalf("got %v", err)
	}
	kc.failSet = false
	secrets, err := v.Resolve(context.Background(), "ns", "test")
	if err != nil || string(secrets[0].Value) != "value" {
		t.Fatalf("got %+v, %v", secrets, err)
	}
	if auth.asks.Load() != 1 {
		t.Fatalf("asks %d, want 1", auth.asks.Load())
	}
	if _, secret := kc.only(t); secret != "new" {
		t.Fatalf("keychain holds %q", secret)
	}
}

func TestToggleKeychain(t *testing.T) {
	kc := &fakeKeychain{items: map[string]string{}}
	auth := &fakeAuth{pass: "pw"}
	v, _ := Open(t.TempDir(), kc, auth)
	v.Create("ns", []byte("pw"), true, Policy{Mode: Every})

	if err := v.SetKeychain(context.Background(), "ns", false); err != nil {
		t.Fatal(err)
	}
	if len(kc.items) != 0 {
		t.Fatal("keychain item left")
	}
	v.Resolve(context.Background(), "ns", "test")
	if auth.confirms.Load() != 0 || auth.asks.Load() != 1 {
		t.Fatalf("off: confirms %d, asks %d", auth.confirms.Load(), auth.asks.Load())
	}

	if err := v.SetKeychain(context.Background(), "ns", true); err != nil {
		t.Fatal(err)
	}
	if _, secret := kc.only(t); secret != "pw" {
		t.Fatalf("keychain holds %q", secret)
	}
	v.Resolve(context.Background(), "ns", "test")
	if auth.confirms.Load() != 1 || auth.asks.Load() != 2 {
		t.Fatalf("on: confirms %d, asks %d", auth.confirms.Load(), auth.asks.Load())
	}
}

func TestRenameAndDelete(t *testing.T) {
	dir := t.TempDir()
	kc := &fakeKeychain{items: map[string]string{}}
	v, _ := Open(dir, kc, &fakeAuth{})
	v.Create("old", []byte("pw"), true, Policy{Mode: Every})
	v.SetEnv("old", "TOKEN", []byte("value"))
	if err := v.Rename("old", "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create("new", []byte("pw"), false, Policy{Mode: Every}); !errors.Is(err, ErrExists) {
		t.Fatalf("create over renamed: %v", err)
	}
	v2, _ := Open(dir, kc, &fakeAuth{})
	if secrets, err := v2.Resolve(context.Background(), "new", "test"); err != nil || string(secrets[0].Value) != "value" {
		t.Fatalf("after rename: %+v, %v", secrets, err)
	}
	if err := v2.Delete(context.Background(), "new"); err != nil {
		t.Fatal(err)
	}
	if len(v2.Namespaces()) != 0 || len(kc.items) != 0 {
		t.Fatal("namespace or keychain item left")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files left: %v", entries)
	}
}

func TestValidation(t *testing.T) {
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, &fakeAuth{})
	for _, name := range []string{"", "Upper", "../x", "-x", "a b"} {
		if _, err := v.Create(name, []byte("pw"), false, Policy{Mode: Every}); !errors.Is(err, ErrInvalidName) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	v.Create("ns", []byte("pw"), false, Policy{Mode: Every})
	for _, key := range []string{"", "1A", "A-B", "../X"} {
		if err := v.SetEnv("ns", key, []byte("x")); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("key %q: %v", key, err)
		}
	}
}

func TestImport(t *testing.T) {
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, &fakeAuth{})
	v.Create("ns", []byte("pw"), true, Policy{Mode: Every})
	keys, err := v.Import("ns", []byte("# comment\nexport TOKEN=\"sk live\"\nURL=postgres://u:p@h/db\n"))
	if err != nil || len(keys) != 2 || keys[0] != "TOKEN" || keys[1] != "URL" {
		t.Fatalf("got %v, %v", keys, err)
	}
	secrets, _ := v.Resolve(context.Background(), "ns", "test")
	if string(secrets[0].Value) != "sk live" || string(secrets[1].Value) != "postgres://u:p@h/db" {
		t.Fatalf("got %+v", secrets)
	}
	if _, err := v.Import("ns", []byte("GOOD=1\nBAD-KEY=2\n")); err == nil {
		t.Fatal("imported an invalid key")
	}
	if ns, _ := v.Namespace("ns"); len(ns.Envs) != 2 {
		t.Fatalf("a failed import set values: %+v", ns.Envs)
	}
}

func TestToggleKeychainFailingToSaveLeavesBothAsTheyWere(t *testing.T) {
	dir := t.TempDir()
	kc := &fakeKeychain{items: map[string]string{}}
	v, _ := Open(dir, kc, &fakeAuth{pass: "pw"})
	v.Create("on", []byte("pw"), true, Policy{Mode: Every})
	v.Create("off", []byte("pw"), false, Policy{Mode: Every})
	account, _ := kc.only(t)
	// meta.json can no longer be replaced.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		os.Chmod(filepath.Join(dir, e.Name()), 0o500)
		defer os.Chmod(filepath.Join(dir, e.Name()), 0o700)
	}

	if err := v.SetKeychain(context.Background(), "on", false); err == nil {
		t.Fatal("turning off saved")
	}
	if ns, _ := v.Namespace("on"); !ns.Keychain {
		t.Fatal("meta says off")
	}
	if a, _ := kc.only(t); a != account {
		t.Fatal("keychain entry gone")
	}

	if err := v.SetKeychain(context.Background(), "off", true); err == nil {
		t.Fatal("turning on saved")
	}
	if ns, _ := v.Namespace("off"); ns.Keychain {
		t.Fatal("meta says on")
	}
	if a, _ := kc.only(t); a != account {
		t.Fatal("keychain entry left behind")
	}
}

// An unlock waiting for the user, whose Keychain entry is missing, would
// store the passphrase it is given; what removes the entry meanwhile waits
// for it, so that the entry stays removed.
func TestKeychainEntryStaysRemovedPastAnUnlockUnderWay(t *testing.T) {
	for name, remove := range map[string]func(v *Vault) error{
		"turned off": func(v *Vault) error { return v.SetKeychain(context.Background(), "ns", false) },
		"deleted":    func(v *Vault) error { return v.Delete(context.Background(), "ns") },
	} {
		kc := &fakeKeychain{items: map[string]string{}}
		auth := &fakeAuth{pass: "pw", hold: make(chan struct{})}
		v, _ := Open(t.TempDir(), kc, auth)
		v.Create("ns", []byte("pw"), true, Policy{Mode: Every})
		account, _ := kc.only(t)
		delete(kc.items, account)

		unlocked := make(chan error)
		go func() {
			_, err := v.Resolve(context.Background(), "ns", "test")
			unlocked <- err
		}()
		for auth.confirms.Load() == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		removed := make(chan error)
		go func() { removed <- remove(v) }()
		select {
		case err := <-removed:
			t.Fatalf("%s: removed while an unlock was under way: %v", name, err)
		case <-time.After(100 * time.Millisecond):
		}
		close(auth.hold)
		if err := <-unlocked; err != nil {
			t.Fatalf("%s: unlock: %v", name, err)
		}
		if err := <-removed; err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(kc.items) != 0 {
			t.Fatalf("%s: keychain entry stored again", name)
		}
	}
}

func TestDotenvReadsBackAsItWas(t *testing.T) {
	v, _ := Open(t.TempDir(), &fakeKeychain{items: map[string]string{}}, &fakeAuth{})
	v.Create("ns", []byte("pw"), true, Policy{Mode: Every})
	want := map[string]string{
		"PIN":    "0123",
		"DOLLAR": "pa$$word ${HOME} $HOME",
		"QUOTES": `say "hi" and 'bye'`,
		"BS":     `back\slash \n literal`,
		"PEM":    "-----BEGIN KEY-----\r\nMIIB\n-----END KEY-----\n",
		"HASH":   "a # not a comment",
		"SPACE":  "  padded  ",
		"EMPTY":  "",
		"UNI":    "密码✓",
	}
	var secrets []Secret
	for k, val := range want {
		secrets = append(secrets, Secret{Key: k, Value: []byte(val)})
	}
	if _, err := v.Import("ns", Dotenv(secrets)); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Resolve(context.Background(), "ns", "test")
	if len(got) != len(want) {
		t.Fatalf("got %d envs", len(got))
	}
	for _, s := range got {
		if string(s.Value) != want[s.Key] {
			t.Errorf("%s: %q, want %q", s.Key, s.Value, want[s.Key])
		}
	}
}
