// Package vault keeps namespaces of environment variables encrypted on
// disk, and hands their values out once the user authorizes it.
//
// Each namespace has an age key pair. Values are encrypted to its public
// key, one file each, so they can be added without unlocking; the private
// key is encrypted with the namespace's passphrase, which the Keychain may
// keep. Unlocking a namespace means holding its private key, for as long as
// its Policy allows.
package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/joho/godotenv"
)

var (
	ErrNotFound    = errors.New("namespace not found")
	ErrExists      = errors.New("namespace already exists")
	ErrInvalidName = errors.New("invalid namespace name: use lowercase letters, digits, '.', '_' and '-'")
	ErrInvalidKey  = errors.New("invalid env key: use letters, digits and '_', not starting with a digit")
	// ErrDenied is what Resolve fails with when the user declines; an
	// Authorizer returns it, or an error wrapping it, when they do.
	ErrDenied = errors.New("authorization denied")
	// ErrKeychainStale is what ChangePassphrase fails with when the new
	// passphrase is in effect but the Keychain still holds the old one. The
	// next unlock asks for the passphrase and puts it right.
	ErrKeychainStale = errors.New("passphrase changed, but the Keychain could not be updated")
)

// workFactor is the scrypt work factor of passphrases, age's default; tests
// lower it.
var workFactor = 18

var (
	namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	keyPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,254}$`)
)

// PolicyMode is how long an authorization lasts.
type PolicyMode string

const (
	Every   PolicyMode = "every"   // each Resolve asks
	TTL     PolicyMode = "ttl"     // one authorization lasts Policy.TTL
	Session PolicyMode = "session" // one authorization lasts until the app quits
)

type Policy struct {
	Mode PolicyMode
	TTL  time.Duration // for TTL
}

// Namespace is what is known of a namespace without unlocking it.
type Namespace struct {
	Name     string
	Policy   Policy
	Keychain bool // whether the Keychain keeps its passphrase
	Envs     []Env
}

type Env struct {
	Key       string
	Sensitive bool
	UpdatedAt time.Time
}

// Secret is an env's value, as Resolve hands it out.
type Secret struct {
	Key       string
	Value     []byte
	Sensitive bool
}

// Authorizer asks the user. Both methods return an error wrapping ErrDenied
// when the user declines, and ctx's error when it is done first.
type Authorizer interface {
	// ConfirmUser asks the person at the Mac to approve, with Touch ID or
	// their login password.
	ConfirmUser(ctx context.Context, reason string) error
	// AskPassphrase asks for the passphrase of namespace ns; retry is set
	// when the one given before was wrong.
	AskPassphrase(ctx context.Context, ns, reason string, retry bool) ([]byte, error)
}

// Keychain keeps passphrases by account. Deleting a missing one is not an
// error.
type Keychain interface {
	Get(account string) ([]byte, error)
	Set(account string, secret []byte) error
	Delete(account string) error
}

// Vault is safe from several goroutines.
type Vault struct {
	dir  string
	kc   Keychain
	auth Authorizer

	// prompting is held while the user is asked, or a namespace's Keychain
	// entry may change: the user is asked one thing at a time, and an
	// unlock that would store the passphrase cannot interleave with turning
	// the Keychain off or deleting the namespace. See hold.
	prompting chan struct{}

	mu     sync.Mutex
	spaces map[string]*space // by name
}

// space is a namespace as the vault holds it.
type space struct {
	id        string
	meta      meta
	recipient age.Recipient
	// identity is the private key while unlocked, until expires (never if
	// zero). gen changes as the namespace is locked, so that an unlock
	// begun before does not outlive it.
	identity *age.HybridIdentity
	expires  time.Time
	gen      int
}

// meta is a namespace's meta.json.
type meta struct {
	Version   int        `json:"version"`
	Name      string     `json:"name"`
	Recipient string     `json:"recipient"`
	Policy    metaPolicy `json:"policy"`
	Keychain  bool       `json:"keychain"`
	Envs      []metaEnv  `json:"envs"`
}

type metaPolicy struct {
	Mode       PolicyMode `json:"mode"`
	TTLSeconds int64      `json:"ttl_seconds,omitempty"`
}

type metaEnv struct {
	Key       string    `json:"key"`
	Sensitive bool      `json:"sensitive"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Open opens the vault kept in dir, creating it if need be.
func Open(dir string, kc Keychain, auth Authorizer) (*Vault, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	v := &Vault{dir: dir, kc: kc, auth: auth, prompting: make(chan struct{}, 1), spaces: map[string]*space{}}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sp, err := v.load(e.Name())
		if err != nil {
			return nil, fmt.Errorf("namespace %s: %w", e.Name(), err)
		}
		v.spaces[sp.meta.Name] = sp
	}
	return v, nil
}

func (v *Vault) load(id string) (*space, error) {
	data, err := os.ReadFile(filepath.Join(v.dir, id, "meta.json"))
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d", m.Version)
	}
	recipient, err := age.ParseHybridRecipient(m.Recipient)
	if err != nil {
		return nil, err
	}
	return &space{id: id, meta: m, recipient: recipient}, nil
}

// Namespaces returns the namespaces by name.
func (v *Vault) Namespaces() []Namespace {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []Namespace
	for _, sp := range v.spaces {
		out = append(out, sp.namespace())
	}
	slices.SortFunc(out, func(a, b Namespace) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Namespace returns the namespace named name, or ErrNotFound.
func (v *Vault) Namespace(name string) (Namespace, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	sp, ok := v.spaces[name]
	if !ok {
		return Namespace{}, ErrNotFound
	}
	return sp.namespace(), nil
}

func (sp *space) namespace() Namespace {
	ns := Namespace{
		Name:     sp.meta.Name,
		Policy:   Policy{Mode: sp.meta.Policy.Mode, TTL: time.Duration(sp.meta.Policy.TTLSeconds) * time.Second},
		Keychain: sp.meta.Keychain,
	}
	for _, e := range sp.meta.Envs {
		ns.Envs = append(ns.Envs, Env(e))
	}
	return ns
}

// Create makes a namespace whose private key the passphrase encrypts, and
// which the Keychain keeps the passphrase of if useKeychain.
func (v *Vault) Create(name string, passphrase []byte, useKeychain bool, p Policy) (Namespace, error) {
	if !namePattern.MatchString(name) {
		return Namespace{}, ErrInvalidName
	}
	if len(passphrase) == 0 {
		return Namespace{}, errors.New("empty passphrase")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.spaces[name]; ok {
		return Namespace{}, ErrExists
	}
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return Namespace{}, err
	}
	wrapped, err := wrapIdentity(identity, passphrase)
	if err != nil {
		return Namespace{}, err
	}
	id := rand.Text()
	sp := &space{
		id:        id,
		recipient: identity.Recipient(),
		meta: meta{
			Version:   1,
			Name:      name,
			Recipient: identity.Recipient().String(),
			Policy:    metaPolicy{Mode: p.Mode, TTLSeconds: int64(p.TTL / time.Second)},
			Keychain:  useKeychain,
			Envs:      []metaEnv{},
		},
	}
	dir := filepath.Join(v.dir, id)
	if err := os.MkdirAll(filepath.Join(dir, "env"), 0o700); err != nil {
		return Namespace{}, err
	}
	err = writeFile(filepath.Join(dir, "identity.age"), wrapped)
	if err == nil {
		err = v.save(sp)
	}
	if err == nil && useKeychain {
		err = v.kc.Set(id, passphrase)
	}
	if err != nil {
		os.RemoveAll(dir)
		return Namespace{}, err
	}
	v.spaces[name] = sp
	return sp.namespace(), nil
}

// Rename renames a namespace; its data and Keychain entry stay as they are.
func (v *Vault) Rename(old, new string) error {
	if !namePattern.MatchString(new) {
		return ErrInvalidName
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	sp, ok := v.spaces[old]
	if !ok {
		return ErrNotFound
	}
	if _, ok := v.spaces[new]; ok {
		return ErrExists
	}
	sp.meta.Name = new
	if err := v.save(sp); err != nil {
		sp.meta.Name = old
		return err
	}
	delete(v.spaces, old)
	v.spaces[new] = sp
	return nil
}

// Delete deletes a namespace, its values and its Keychain entry, once the
// user is asked nothing else.
func (v *Vault) Delete(ctx context.Context, name string) error {
	release, err := v.hold(ctx)
	if err != nil {
		return err
	}
	defer release()
	v.mu.Lock()
	defer v.mu.Unlock()
	sp, ok := v.spaces[name]
	if !ok {
		return ErrNotFound
	}
	if err := v.kc.Delete(sp.id); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(v.dir, sp.id)); err != nil {
		return err
	}
	delete(v.spaces, name)
	sp.lock()
	return nil
}

// SetPolicy changes how long an authorization of the namespace lasts, and
// locks it.
func (v *Vault) SetPolicy(name string, p Policy) error {
	return v.update(name, func(sp *space) error {
		sp.meta.Policy = metaPolicy{Mode: p.Mode, TTLSeconds: int64(p.TTL / time.Second)}
		sp.lock()
		return nil
	})
}

// SetEnv sets the value of key in the namespace, which need not be
// unlocked. A new key is sensitive.
func (v *Vault) SetEnv(name, key string, value []byte) error {
	if !keyPattern.MatchString(key) {
		return ErrInvalidKey
	}
	return v.update(name, func(sp *space) error {
		var b bytes.Buffer
		w, err := age.Encrypt(&b, sp.recipient)
		if err != nil {
			return err
		}
		w.Write(value)
		if err := w.Close(); err != nil {
			return err
		}
		if err := writeFile(v.envPath(sp, key), b.Bytes()); err != nil {
			return err
		}
		now := time.Now().UTC()
		if i := sp.env(key); i >= 0 {
			sp.meta.Envs[i].UpdatedAt = now
		} else {
			sp.meta.Envs = append(sp.meta.Envs, metaEnv{Key: key, Sensitive: true, UpdatedAt: now})
			slices.SortFunc(sp.meta.Envs, func(a, b metaEnv) int { return strings.Compare(a.Key, b.Key) })
		}
		return nil
	})
}

// SetSensitive sets whether key's value is masked in output.
func (v *Vault) SetSensitive(name, key string, sensitive bool) error {
	return v.update(name, func(sp *space) error {
		i := sp.env(key)
		if i < 0 {
			return fmt.Errorf("no env %s", key)
		}
		sp.meta.Envs[i].Sensitive = sensitive
		return nil
	})
}

// DeleteEnv deletes key from the namespace.
func (v *Vault) DeleteEnv(name, key string) error {
	return v.update(name, func(sp *space) error {
		i := sp.env(key)
		if i < 0 {
			return nil
		}
		if err := os.Remove(v.envPath(sp, key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		sp.meta.Envs = slices.Delete(sp.meta.Envs, i, i+1)
		return nil
	})
}

// Import sets the values of a .env file in the namespace, replacing those
// of the same keys, and returns the keys set. Nothing is set if any key is
// invalid. Removing the file is up to the caller.
func (v *Vault) Import(name string, dotenv []byte) ([]string, error) {
	values, err := godotenv.UnmarshalBytes(dotenv)
	if err != nil {
		return nil, err
	}
	var keys []string
	for key := range values {
		if !keyPattern.MatchString(key) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidKey, key)
		}
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if err := v.SetEnv(name, key, []byte(values[key])); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// Resolve returns the values of the namespace, asking the user first unless
// an authorization within its Policy holds. Under TTL and Session, requests
// that come while the user is asked share their answer; under Every, each
// asks. It fails with ErrNotFound, an error wrapping ErrDenied, or ctx's
// error, which also dismisses the question asked.
func (v *Vault) Resolve(ctx context.Context, name, reason string) ([]Secret, error) {
	identity, err := v.unlock(ctx, name, reason)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	sp, ok := v.spaces[name]
	if !ok {
		v.mu.Unlock()
		return nil, ErrNotFound
	}
	envs := slices.Clone(sp.meta.Envs)
	paths := make([]string, len(envs))
	for i, e := range envs {
		paths[i] = v.envPath(sp, e.Key)
	}
	v.mu.Unlock()

	secrets := make([]Secret, len(envs))
	for i, e := range envs {
		data, err := os.ReadFile(paths[i])
		if err != nil {
			return nil, err
		}
		r, err := age.Decrypt(bytes.NewReader(data), identity)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", e.Key, err)
		}
		value, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", e.Key, err)
		}
		secrets[i] = Secret{Key: e.Key, Value: value, Sensitive: e.Sensitive}
	}
	return secrets, nil
}

// unlock returns the namespace's private key, from its unlock if one holds,
// or else asking the user, and keeping it as the policy allows.
func (v *Vault) unlock(ctx context.Context, name, reason string) (*age.HybridIdentity, error) {
	if identity, _, err := v.unlocked(name); identity != nil || err != nil {
		return identity, err
	}
	release, err := v.hold(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	// The user may have unlocked it, answering an earlier request.
	identity, sp, err := v.unlocked(name)
	if identity != nil || err != nil {
		return identity, err
	}
	v.mu.Lock()
	id, keychain, policy, gen := sp.id, sp.meta.Keychain, sp.meta.Policy, sp.gen
	v.mu.Unlock()

	identity, err = v.authorize(ctx, id, name, keychain, reason)
	if err != nil {
		return nil, err
	}
	if policy.Mode != Every {
		v.mu.Lock()
		if sp.gen == gen {
			sp.identity = identity
			if policy.Mode == TTL {
				sp.expires = time.Now().Add(time.Duration(policy.TTLSeconds) * time.Second)
			}
		}
		v.mu.Unlock()
	}
	return identity, nil
}

// unlocked returns the namespace, and its private key if it is unlocked.
func (v *Vault) unlocked(name string) (*age.HybridIdentity, *space, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	sp, ok := v.spaces[name]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if sp.identity != nil && !sp.expires.IsZero() && !time.Now().Before(sp.expires) {
		sp.lock()
	}
	return sp.identity, sp, nil
}

// authorize asks the user, and returns the namespace's private key. With
// the Keychain, the user confirms and the Keychain's passphrase decrypts
// the key; if it is missing or wrong, the user gives the passphrase, which
// the Keychain then keeps.
func (v *Vault) authorize(ctx context.Context, id, name string, keychain bool, reason string) (*age.HybridIdentity, error) {
	wrapped, err := os.ReadFile(filepath.Join(v.dir, id, "identity.age"))
	if err != nil {
		return nil, err
	}
	if !keychain {
		identity, _, err := v.askPassphrase(ctx, name, reason, wrapped)
		return identity, err
	}
	if err := v.auth.ConfirmUser(ctx, reason); err != nil {
		return nil, err
	}
	if passphrase, err := v.kc.Get(id); err == nil {
		if identity, err := unwrapIdentity(wrapped, passphrase); err == nil {
			return identity, nil
		}
	}
	identity, passphrase, err := v.askPassphrase(ctx, name, reason, wrapped)
	if err != nil {
		return nil, err
	}
	// Failing, it asks again next time.
	v.kc.Set(id, passphrase)
	return identity, nil
}

// askPassphrase asks for the passphrase until it decrypts the private key.
func (v *Vault) askPassphrase(ctx context.Context, name, reason string, wrapped []byte) (*age.HybridIdentity, []byte, error) {
	for retry := false; ; retry = true {
		passphrase, err := v.auth.AskPassphrase(ctx, name, reason, retry)
		if err != nil {
			return nil, nil, err
		}
		if identity, err := unwrapIdentity(wrapped, passphrase); err == nil {
			return identity, passphrase, nil
		}
	}
}

// SetKeychain sets whether the Keychain keeps the namespace's passphrase.
// Turning it on asks the user for the passphrase.
func (v *Vault) SetKeychain(ctx context.Context, name string, on bool) error {
	release, err := v.hold(ctx)
	if err != nil {
		return err
	}
	defer release()
	v.mu.Lock()
	sp, ok := v.spaces[name]
	if !ok {
		v.mu.Unlock()
		return ErrNotFound
	}
	id := sp.id
	v.mu.Unlock()

	if on {
		wrapped, err := os.ReadFile(filepath.Join(v.dir, id, "identity.age"))
		if err != nil {
			return err
		}
		_, passphrase, err := v.askPassphrase(ctx, name, "store the passphrase in the Keychain", wrapped)
		if err != nil {
			return err
		}
		if err := v.kc.Set(id, passphrase); err != nil {
			return err
		}
		if err := v.setKeychainMeta(name, true); err != nil {
			v.kc.Delete(id)
			return err
		}
		return nil
	}
	// The meta goes first: were the entry left behind, unlocking would no
	// longer read it, while an entry gone under a meta still on would be
	// asked for and stored again.
	if err := v.setKeychainMeta(name, false); err != nil {
		return err
	}
	if err := v.kc.Delete(id); err != nil {
		v.setKeychainMeta(name, true)
		return err
	}
	return nil
}

// hold waits until the user is asked nothing else, and keeps it so until
// release is called; see prompting.
func (v *Vault) hold(ctx context.Context) (release func(), err error) {
	select {
	case v.prompting <- struct{}{}:
		return func() { <-v.prompting }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (v *Vault) setKeychainMeta(name string, on bool) error {
	return v.update(name, func(sp *space) error {
		sp.meta.Keychain = on
		return nil
	})
}

// ChangePassphrase asks the user, then encrypts the namespace's private key
// with a new passphrase, and puts it in the Keychain if it keeps the old
// one. It fails with ErrKeychainStale if only the last step fails.
func (v *Vault) ChangePassphrase(ctx context.Context, name string, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}
	release, err := v.hold(ctx)
	if err != nil {
		return err
	}
	defer release()
	v.mu.Lock()
	sp, ok := v.spaces[name]
	if !ok {
		v.mu.Unlock()
		return ErrNotFound
	}
	id, keychain := sp.id, sp.meta.Keychain
	v.mu.Unlock()

	identity, err := v.authorize(ctx, id, name, keychain, "change the passphrase")
	if err != nil {
		return err
	}
	wrapped, err := wrapIdentity(identity, passphrase)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(v.dir, id, "identity.age"), wrapped); err != nil {
		return err
	}
	if keychain {
		if err := v.kc.Set(id, passphrase); err != nil {
			return fmt.Errorf("%w: %v", ErrKeychainStale, err)
		}
	}
	return nil
}

// Lock forgets the namespace's authorization.
func (v *Vault) Lock(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if sp, ok := v.spaces[name]; ok {
		sp.lock()
	}
}

// LockAll forgets every authorization.
func (v *Vault) LockAll() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, sp := range v.spaces {
		sp.lock()
	}
}

func (sp *space) lock() {
	sp.identity, sp.expires = nil, time.Time{}
	sp.gen++
}

// update changes a namespace with v.mu held, and saves its meta.json. If
// either fails, the meta is as it was.
func (v *Vault) update(name string, change func(*space) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	sp, ok := v.spaces[name]
	if !ok {
		return ErrNotFound
	}
	before := sp.meta
	before.Envs = slices.Clone(sp.meta.Envs)
	err := change(sp)
	if err == nil {
		err = v.save(sp)
	}
	if err != nil {
		sp.meta = before
	}
	return err
}

func (v *Vault) save(sp *space) error {
	data, err := json.MarshalIndent(sp.meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(v.dir, sp.id, "meta.json"), data)
}

func (sp *space) env(key string) int {
	return slices.IndexFunc(sp.meta.Envs, func(e metaEnv) bool { return e.Key == key })
}

// envPath is where key's value is kept. The name is the key in hex, since
// the file system may not tell keys that differ in case apart.
func (v *Vault) envPath(sp *space, key string) string {
	return filepath.Join(v.dir, sp.id, "env", hex.EncodeToString([]byte(key))+".age")
}

func wrapIdentity(identity *age.HybridIdentity, passphrase []byte) ([]byte, error) {
	r, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(workFactor)
	var b bytes.Buffer
	w, err := age.Encrypt(&b, r)
	if err != nil {
		return nil, err
	}
	io.WriteString(w, identity.String())
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func unwrapIdentity(wrapped, passphrase []byte) (*age.HybridIdentity, error) {
	si, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(wrapped), si)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return age.ParseHybridIdentity(strings.TrimSpace(string(data)))
}

// writeFile replaces the file at path with data, all at once.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
