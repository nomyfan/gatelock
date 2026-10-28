// Package vault keeps vaults of environment variables encrypted on
// disk, and hands their values out once the user authorizes it.
//
// Each vault has an age key pair. Values are encrypted to its public
// key, one file each, so they can be added without unlocking; the private
// key is encrypted with the vault's passphrase, which the Keychain may
// keep. Unlocking a vault means holding its private key, for as long as
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
	ErrNotFound    = errors.New("vault not found")
	ErrExists      = errors.New("vault already exists")
	ErrInvalidName = errors.New("invalid vault name: use lowercase letters, digits, '.', '_' and '-'")
	ErrInvalidKey  = errors.New("invalid env key: use letters, digits and '_', not starting with a digit")
	ErrKeyExists   = errors.New("env already exists")
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

// Vault is what is known of a vault without unlocking it.
type Vault struct {
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
	// AskPassphrase asks for the passphrase of vault; retry is set
	// when the one given before was wrong.
	AskPassphrase(ctx context.Context, vault, reason string, retry bool) ([]byte, error)
}

// Keychain keeps passphrases by account. Deleting a missing one is not an
// error.
type Keychain interface {
	Get(account string) ([]byte, error)
	Set(account string, secret []byte) error
	Delete(account string) error
}

// Store keeps the vaults. It is safe from several goroutines.
type Store struct {
	dir  string
	kc   Keychain
	auth Authorizer

	// prompting is held while the user is asked, or a vault's Keychain
	// entry may change: the user is asked one thing at a time, and an
	// unlock that would store the passphrase cannot interleave with turning
	// the Keychain off or deleting the vault. See hold.
	prompting chan struct{}

	mu     sync.Mutex
	vaults map[string]*stored // by name
}

// stored is a vault as the Store holds it.
type stored struct {
	id        string
	meta      meta
	recipient age.Recipient
	// identity is the private key while unlocked, until expires (never if
	// zero). gen changes as the vault is locked, so that an unlock
	// begun before does not outlive it.
	identity *age.HybridIdentity
	expires  time.Time
	gen      int
}

// meta is a vault's meta.json.
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

// Open opens the store kept in dir, creating it if need be.
func Open(dir string, kc Keychain, auth Authorizer) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, kc: kc, auth: auth, prompting: make(chan struct{}, 1), vaults: map[string]*stored{}}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sv, err := s.load(e.Name())
		if err != nil {
			return nil, fmt.Errorf("vault %s: %w", e.Name(), err)
		}
		s.vaults[sv.meta.Name] = sv
	}
	return s, nil
}

func (s *Store) load(id string) (*stored, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, id, "meta.json"))
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
	return &stored{id: id, meta: m, recipient: recipient}, nil
}

// Vaults returns the vaults by name.
func (s *Store) Vaults() []Vault {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Vault
	for _, sv := range s.vaults {
		out = append(out, sv.vault())
	}
	slices.SortFunc(out, func(a, b Vault) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Vault returns the vault named name, or ErrNotFound.
func (s *Store) Vault(name string) (Vault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sv, ok := s.vaults[name]
	if !ok {
		return Vault{}, ErrNotFound
	}
	return sv.vault(), nil
}

func (sv *stored) vault() Vault {
	vault := Vault{
		Name:     sv.meta.Name,
		Policy:   Policy{Mode: sv.meta.Policy.Mode, TTL: time.Duration(sv.meta.Policy.TTLSeconds) * time.Second},
		Keychain: sv.meta.Keychain,
	}
	for _, e := range sv.meta.Envs {
		vault.Envs = append(vault.Envs, Env(e))
	}
	return vault
}

// Create makes a vault whose private key the passphrase encrypts, and
// which the Keychain keeps the passphrase of if useKeychain.
func (s *Store) Create(name string, passphrase []byte, useKeychain bool, p Policy) (Vault, error) {
	if !namePattern.MatchString(name) {
		return Vault{}, ErrInvalidName
	}
	if len(passphrase) == 0 {
		return Vault{}, errors.New("empty passphrase")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.vaults[name]; ok {
		return Vault{}, ErrExists
	}
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return Vault{}, err
	}
	wrapped, err := wrapIdentity(identity, passphrase)
	if err != nil {
		return Vault{}, err
	}
	id := rand.Text()
	sv := &stored{
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
	dir := filepath.Join(s.dir, id)
	if err := os.MkdirAll(filepath.Join(dir, "env"), 0o700); err != nil {
		return Vault{}, err
	}
	err = writeFile(filepath.Join(dir, "identity.age"), wrapped)
	if err == nil {
		err = s.save(sv)
	}
	if err == nil && useKeychain {
		err = s.kc.Set(id, passphrase)
	}
	if err != nil {
		os.RemoveAll(dir)
		return Vault{}, err
	}
	s.vaults[name] = sv
	return sv.vault(), nil
}

// Rename renames a vault; its data and Keychain entry stay as they are.
func (s *Store) Rename(old, new string) error {
	if !namePattern.MatchString(new) {
		return ErrInvalidName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sv, ok := s.vaults[old]
	if !ok {
		return ErrNotFound
	}
	if _, ok := s.vaults[new]; ok {
		return ErrExists
	}
	sv.meta.Name = new
	if err := s.save(sv); err != nil {
		sv.meta.Name = old
		return err
	}
	delete(s.vaults, old)
	s.vaults[new] = sv
	return nil
}

// Delete deletes a vault, its values and its Keychain entry, once the
// user is asked nothing else.
func (s *Store) Delete(ctx context.Context, name string) error {
	release, err := s.hold(ctx)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	sv, ok := s.vaults[name]
	if !ok {
		return ErrNotFound
	}
	if err := s.kc.Delete(sv.id); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(s.dir, sv.id)); err != nil {
		return err
	}
	delete(s.vaults, name)
	sv.lock()
	return nil
}

// SetPolicy changes how long an authorization of the vault lasts, and
// locks it.
func (s *Store) SetPolicy(name string, p Policy) error {
	return s.update(name, func(sv *stored) error {
		sv.meta.Policy = metaPolicy{Mode: p.Mode, TTLSeconds: int64(p.TTL / time.Second)}
		sv.lock()
		return nil
	})
}

// SetEnv sets the value of key in the vault, which need not be
// unlocked. A new key is sensitive.
func (s *Store) SetEnv(name, key string, value []byte) error {
	if !keyPattern.MatchString(key) {
		return ErrInvalidKey
	}
	return s.update(name, func(sv *stored) error {
		var b bytes.Buffer
		w, err := age.Encrypt(&b, sv.recipient)
		if err != nil {
			return err
		}
		w.Write(value)
		if err := w.Close(); err != nil {
			return err
		}
		if err := writeFile(s.envPath(sv, key), b.Bytes()); err != nil {
			return err
		}
		now := time.Now().UTC()
		if i := sv.env(key); i >= 0 {
			sv.meta.Envs[i].UpdatedAt = now
		} else {
			sv.meta.Envs = append(sv.meta.Envs, metaEnv{Key: key, Sensitive: true, UpdatedAt: now})
			sortEnvs(sv.meta.Envs)
		}
		return nil
	})
}

// SetSensitive sets whether key's value is masked in output.
func (s *Store) SetSensitive(name, key string, sensitive bool) error {
	return s.update(name, func(sv *stored) error {
		i := sv.env(key)
		if i < 0 {
			return fmt.Errorf("no env %s", key)
		}
		sv.meta.Envs[i].Sensitive = sensitive
		return nil
	})
}

// RenameEnv renames the env old to new, which need not be unlocked: the
// value stays encrypted as it was. Renaming to a key the vault has is
// ErrKeyExists.
func (s *Store) RenameEnv(name, old, new string) error {
	if !keyPattern.MatchString(new) {
		return ErrInvalidKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sv, ok := s.vaults[name]
	if !ok {
		return ErrNotFound
	}
	i := sv.env(old)
	if i < 0 {
		return fmt.Errorf("no env %s", old)
	}
	if new == old {
		return nil
	}
	if sv.env(new) >= 0 {
		return ErrKeyExists
	}
	// The value is linked under the new name, and unlinked from the old
	// once the meta names the new key, so that the file the meta names is
	// there whenever this stops. A file under the new name already is one
	// such a stop left, which the meta does not name.
	from, to := s.envPath(sv, old), s.envPath(sv, new)
	if err := os.Remove(to); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Link(from, to); err != nil {
		return err
	}
	before := slices.Clone(sv.meta.Envs)
	sv.meta.Envs[i].Key = new
	sortEnvs(sv.meta.Envs)
	if err := s.save(sv); err != nil {
		sv.meta.Envs = before
		os.Remove(to)
		return err
	}
	// Left behind, the old file would only take space.
	os.Remove(from)
	return nil
}

// DeleteEnv deletes key from the vault.
func (s *Store) DeleteEnv(name, key string) error {
	return s.update(name, func(sv *stored) error {
		i := sv.env(key)
		if i < 0 {
			return nil
		}
		if err := os.Remove(s.envPath(sv, key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		sv.meta.Envs = slices.Delete(sv.meta.Envs, i, i+1)
		return nil
	})
}

// Import sets the values of a .env file in the vault, replacing those
// of the same keys, and returns the keys set. Nothing is set if any key is
// invalid. Removing the file is up to the caller.
func (s *Store) Import(name string, dotenv []byte) ([]string, error) {
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
		if err := s.SetEnv(name, key, []byte(values[key])); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// dotenvEscaper escapes a value within double quotes, as godotenv reads
// it back: without expanding $VARS, and with its line breaks.
var dotenvEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`, "\r", `\r`)

// Dotenv returns secrets as a .env file, which Import reads back as they
// are. Every value is quoted: godotenv.Marshal would write "0123" as 123.
func Dotenv(secrets []Secret) []byte {
	var b strings.Builder
	for _, s := range secrets {
		fmt.Fprintf(&b, "%s=\"%s\"\n", s.Key, dotenvEscaper.Replace(string(s.Value)))
	}
	return []byte(b.String())
}

// DotenvExample writes the keys of envs as a .env.example, each with no
// value.
func DotenvExample(envs []Env) []byte {
	var b strings.Builder
	for _, e := range envs {
		b.WriteString(e.Key + "=\n")
	}
	return []byte(b.String())
}

// Resolve returns the values of the vault, asking the user first unless
// an authorization within its Policy holds. Under TTL and Session, requests
// that come while the user is asked share their answer; under Every, each
// asks. It fails with ErrNotFound, an error wrapping ErrDenied, or ctx's
// error, which also dismisses the question asked.
func (s *Store) Resolve(ctx context.Context, name, reason string) ([]Secret, error) {
	identity, err := s.unlock(ctx, name, reason)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	sv, ok := s.vaults[name]
	if !ok {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	envs := slices.Clone(sv.meta.Envs)
	paths := make([]string, len(envs))
	for i, e := range envs {
		paths[i] = s.envPath(sv, e.Key)
	}
	s.mu.Unlock()

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

// unlock returns the vault's private key, from its unlock if one holds,
// or else asking the user, and keeping it as the policy allows.
func (s *Store) unlock(ctx context.Context, name, reason string) (*age.HybridIdentity, error) {
	if identity, _, err := s.unlocked(name); identity != nil || err != nil {
		return identity, err
	}
	release, err := s.hold(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	// The user may have unlocked it, answering an earlier request.
	identity, sv, err := s.unlocked(name)
	if identity != nil || err != nil {
		return identity, err
	}
	s.mu.Lock()
	id, keychain, policy, gen := sv.id, sv.meta.Keychain, sv.meta.Policy, sv.gen
	s.mu.Unlock()

	identity, err = s.authorize(ctx, id, name, keychain, reason)
	if err != nil {
		return nil, err
	}
	if policy.Mode != Every {
		s.mu.Lock()
		if sv.gen == gen {
			sv.identity = identity
			if policy.Mode == TTL {
				sv.expires = time.Now().Add(time.Duration(policy.TTLSeconds) * time.Second)
			}
		}
		s.mu.Unlock()
	}
	return identity, nil
}

// unlocked returns the vault, and its private key if it is unlocked.
func (s *Store) unlocked(name string) (*age.HybridIdentity, *stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sv, ok := s.vaults[name]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if sv.identity != nil && !sv.expires.IsZero() && !time.Now().Before(sv.expires) {
		sv.lock()
	}
	return sv.identity, sv, nil
}

// authorize asks the user, and returns the vault's private key. With
// the Keychain, the user confirms and the Keychain's passphrase decrypts
// the key; if it is missing or wrong, the user gives the passphrase, which
// the Keychain then keeps.
func (s *Store) authorize(ctx context.Context, id, name string, keychain bool, reason string) (*age.HybridIdentity, error) {
	wrapped, err := os.ReadFile(filepath.Join(s.dir, id, "identity.age"))
	if err != nil {
		return nil, err
	}
	if !keychain {
		identity, _, err := s.askPassphrase(ctx, name, reason, wrapped)
		return identity, err
	}
	if err := s.auth.ConfirmUser(ctx, reason); err != nil {
		return nil, err
	}
	if passphrase, err := s.kc.Get(id); err == nil {
		if identity, err := unwrapIdentity(wrapped, passphrase); err == nil {
			return identity, nil
		}
	}
	identity, passphrase, err := s.askPassphrase(ctx, name, reason, wrapped)
	if err != nil {
		return nil, err
	}
	// Failing, it asks again next time.
	s.kc.Set(id, passphrase)
	return identity, nil
}

// askPassphrase asks for the passphrase until it decrypts the private key.
func (s *Store) askPassphrase(ctx context.Context, name, reason string, wrapped []byte) (*age.HybridIdentity, []byte, error) {
	for retry := false; ; retry = true {
		passphrase, err := s.auth.AskPassphrase(ctx, name, reason, retry)
		if err != nil {
			return nil, nil, err
		}
		if identity, err := unwrapIdentity(wrapped, passphrase); err == nil {
			return identity, passphrase, nil
		}
	}
}

// SetKeychain sets whether the Keychain keeps the vault's passphrase.
// Turning it on asks the user for the passphrase.
func (s *Store) SetKeychain(ctx context.Context, name string, on bool) error {
	release, err := s.hold(ctx)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	sv, ok := s.vaults[name]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	id := sv.id
	s.mu.Unlock()

	if on {
		wrapped, err := os.ReadFile(filepath.Join(s.dir, id, "identity.age"))
		if err != nil {
			return err
		}
		_, passphrase, err := s.askPassphrase(ctx, name, "store the passphrase in the Keychain", wrapped)
		if err != nil {
			return err
		}
		if err := s.kc.Set(id, passphrase); err != nil {
			return err
		}
		if err := s.setKeychainMeta(name, true); err != nil {
			s.kc.Delete(id)
			return err
		}
		return nil
	}
	// The meta goes first: were the entry left behind, unlocking would no
	// longer read it, while an entry gone under a meta still on would be
	// asked for and stored again.
	if err := s.setKeychainMeta(name, false); err != nil {
		return err
	}
	if err := s.kc.Delete(id); err != nil {
		s.setKeychainMeta(name, true)
		return err
	}
	return nil
}

// hold waits until the user is asked nothing else, and keeps it so until
// release is called; see prompting.
func (s *Store) hold(ctx context.Context) (release func(), err error) {
	select {
	case s.prompting <- struct{}{}:
		return func() { <-s.prompting }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Store) setKeychainMeta(name string, on bool) error {
	return s.update(name, func(sv *stored) error {
		sv.meta.Keychain = on
		return nil
	})
}

// ChangePassphrase asks the user, then encrypts the vault's private key
// with a new passphrase, and puts it in the Keychain if it keeps the old
// one. It fails with ErrKeychainStale if only the last step fails.
func (s *Store) ChangePassphrase(ctx context.Context, name string, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}
	release, err := s.hold(ctx)
	if err != nil {
		return err
	}
	defer release()
	s.mu.Lock()
	sv, ok := s.vaults[name]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	id, keychain := sv.id, sv.meta.Keychain
	s.mu.Unlock()

	identity, err := s.authorize(ctx, id, name, keychain, "change the passphrase")
	if err != nil {
		return err
	}
	wrapped, err := wrapIdentity(identity, passphrase)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(s.dir, id, "identity.age"), wrapped); err != nil {
		return err
	}
	if keychain {
		if err := s.kc.Set(id, passphrase); err != nil {
			return fmt.Errorf("%w: %v", ErrKeychainStale, err)
		}
	}
	return nil
}

// Lock forgets the vault's authorization.
func (s *Store) Lock(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sv, ok := s.vaults[name]; ok {
		sv.lock()
	}
}

// LockAll forgets every authorization.
func (s *Store) LockAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sv := range s.vaults {
		sv.lock()
	}
}

func (sv *stored) lock() {
	sv.identity, sv.expires = nil, time.Time{}
	sv.gen++
}

// update changes a vault with s.mu held, and saves its meta.json. If
// either fails, the meta is as it was.
func (s *Store) update(name string, change func(*stored) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sv, ok := s.vaults[name]
	if !ok {
		return ErrNotFound
	}
	before := sv.meta
	before.Envs = slices.Clone(sv.meta.Envs)
	err := change(sv)
	if err == nil {
		err = s.save(sv)
	}
	if err != nil {
		sv.meta = before
	}
	return err
}

func (s *Store) save(sv *stored) error {
	data, err := json.MarshalIndent(sv.meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(s.dir, sv.id, "meta.json"), data)
}

func sortEnvs(envs []metaEnv) {
	slices.SortFunc(envs, func(a, b metaEnv) int { return strings.Compare(a.Key, b.Key) })
}

func (sv *stored) env(key string) int {
	return slices.IndexFunc(sv.meta.Envs, func(e metaEnv) bool { return e.Key == key })
}

// envPath is where key's value is kept. The name is the key in hex, since
// the file system may not tell keys that differ in case apart.
func (s *Store) envPath(sv *stored, key string) string {
	return filepath.Join(s.dir, sv.id, "env", hex.EncodeToString([]byte(key))+".age")
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
