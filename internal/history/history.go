// Package history keeps the record of the commands `gatelock run` ran: the
// ones running, which the user can stop, and the last ones that ended,
// with their masked output.
package history

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type Status string

const (
	Authorizing Status = "authorizing" // waiting for the user to authorize it
	Running     Status = "running"
	Exited      Status = "exited"
	Stopped     Status = "stopped" // exited after the user stopped it
	Denied      Status = "denied"  // the user did not authorize it
	Failed      Status = "failed"  // it could not be started
	Lost        Status = "lost"    // gatelock run went away before it ended
)

// Ended reports whether an activity with the status is over.
func (s Status) Ended() bool { return s != Authorizing && s != Running }

// Activity is a command's record.
type Activity struct {
	ID        string    `json:"id"`
	Vault     string    `json:"vault"`
	Argv      []string  `json:"argv"`
	Cwd       string    `json:"cwd"`
	PGID      int       `json:"pgid,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
	Status    Status    `json:"status"`
	ExitCode  int       `json:"exit_code"`
	// Truncated is set once the beginning of the output was dropped.
	Truncated bool `json:"truncated,omitempty"`
	// Caller names the program that ran it, if known: a hint, as a
	// program can pass for another.
	Caller string `json:"caller,omitempty"`
}

const (
	// keep is how many activities are kept.
	keep = 200
	// Output beyond maxOutput is cut back to its last keptOutput bytes.
	maxOutput  = 4 << 20
	keptOutput = 2 << 20
)

// Store is safe from several goroutines.
type Store struct {
	dir      string
	onChange func()

	mu         sync.Mutex
	activities map[string]*Activity
	records    map[string]*Record // of the activities not ended
}

// Record is an activity not ended, as it goes.
type Record struct {
	s             *Store
	activity      *Activity
	stop          func()
	stopRequested bool
	out           *os.File
	size          int64
}

// Open opens the store kept in dir, creating it if need be. Activities
// left not ended, by an app that quit, are marked lost. onChange is
// called, without locks held, after every change.
func Open(dir string, onChange func()) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, onChange: onChange, activities: map[string]*Activity{}, records: map[string]*Record{}}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name(), "meta.json"))
		if err != nil {
			// An activity removed half way, or not one at all.
			os.RemoveAll(filepath.Join(dir, e.Name()))
			continue
		}
		var r Activity
		if err := json.Unmarshal(data, &r); err != nil {
			os.RemoveAll(filepath.Join(dir, e.Name()))
			continue
		}
		if !r.Status.Ended() {
			r.Status = Lost
			if err := s.save(&r); err != nil {
				return nil, err
			}
		}
		s.activities[r.ID] = &r
	}
	s.prune()
	return s, nil
}

// Begin records a command's activity, waiting to be authorized. caller
// names the program that ran it, or is empty; stop asks the command to
// stop.
func (s *Store) Begin(vault string, argv []string, cwd, caller string, stop func()) (*Record, error) {
	r := &Activity{
		ID:        newID(),
		Vault:     vault,
		Argv:      argv,
		Cwd:       cwd,
		Caller:    caller,
		StartedAt: time.Now().UTC(),
		Status:    Authorizing,
	}
	if err := os.Mkdir(filepath.Join(s.dir, r.ID), 0o700); err != nil {
		return nil, err
	}
	out, err := os.OpenFile(filepath.Join(s.dir, r.ID, "output.log"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := s.save(r); err != nil {
		out.Close()
		return nil, err
	}
	rec := &Record{s: s, activity: r, stop: stop, out: out}
	s.mu.Lock()
	s.activities[r.ID] = r
	s.records[r.ID] = rec
	s.prune()
	s.mu.Unlock()
	s.onChange()
	return rec, nil
}

func newID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return time.Now().UTC().Format("20060102T150405.000000000") + "-" + hex.EncodeToString(b)
}

// ID returns the activity's id.
func (rec *Record) ID() string { return rec.activity.ID }

// Authorized records that the activity was authorized and is starting.
func (rec *Record) Authorized() { rec.change(func(r *Activity) { r.Status = Running }) }

// Started records the process group of the command.
func (rec *Record) Started(pgid int) { rec.change(func(r *Activity) { r.PGID = pgid }) }

// Write appends masked output.
func (rec *Record) Write(p []byte) (int, error) {
	s := rec.s
	s.mu.Lock()
	n, err := rec.out.WriteAt(p, rec.size)
	rec.size += int64(n)
	var truncated *Activity
	if err == nil && rec.size > maxOutput {
		tail := make([]byte, keptOutput)
		if _, err = rec.out.ReadAt(tail, rec.size-keptOutput); err == nil {
			if err = rec.out.Truncate(0); err == nil {
				_, err = rec.out.WriteAt(tail, 0)
			}
			rec.size = keptOutput
			if !rec.activity.Truncated {
				rec.activity.Truncated = true
				r := *rec.activity
				truncated = &r
			}
		}
	}
	s.mu.Unlock()
	if truncated != nil {
		s.save(truncated)
	}
	s.onChange()
	return n, err
}

// Exited records that the command exited with code: stopped, if the user
// had asked it to stop.
func (rec *Record) Exited(code int) {
	rec.end(func(r *Activity) {
		r.Status = Exited
		if rec.stopRequested {
			r.Status = Stopped
		}
		r.ExitCode = code
	})
}

// End records that the activity ended otherwise than by the command exiting:
// Denied, Failed or Lost.
func (rec *Record) End(status Status) { rec.end(func(r *Activity) { r.Status = status }) }

func (rec *Record) end(change func(*Activity)) {
	rec.change(func(r *Activity) {
		change(r)
		r.EndedAt = time.Now().UTC()
		delete(rec.s.records, r.ID)
		rec.out.Close()
	})
}

func (rec *Record) change(change func(*Activity)) {
	s := rec.s
	s.mu.Lock()
	change(rec.activity)
	r := *rec.activity
	s.mu.Unlock()
	s.save(&r)
	s.onChange()
}

// List returns the activities not ended, then the others, the latest first.
func (s *Store) List() []Activity {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Activity, 0, len(s.activities))
	for _, r := range s.activities {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b Activity) int {
		if a.Status.Ended() != b.Status.Ended() {
			if a.Status.Ended() {
				return 1
			}
			return -1
		}
		return cmp.Compare(b.ID, a.ID)
	})
	return out
}

// Running reports how many activities are not ended.
func (s *Store) Running() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Output returns the masked output kept of an activity.
func (s *Store) Output(id string) ([]byte, error) {
	s.mu.Lock()
	_, ok := s.activities[id]
	s.mu.Unlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	f, err := os.Open(filepath.Join(s.dir, id, "output.log"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Stop asks an activity to stop; one ended is left as it is.
func (s *Store) Stop(id string) {
	s.mu.Lock()
	rec, ok := s.records[id]
	if ok {
		rec.stopRequested = true
	}
	s.mu.Unlock()
	if ok {
		rec.stop()
	}
}

// StopAll asks every activity to stop.
func (s *Store) StopAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.Stop(id)
	}
}

// Clear removes the ended activities, with their output; the others are
// kept, so that they can still be stopped. An activity whose meta.json
// could not be removed is kept too, as it would come back on the next
// Open.
func (s *Store) Clear() error {
	s.mu.Lock()
	var ended []string
	for id, r := range s.activities {
		if r.Status.Ended() {
			ended = append(ended, id)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, id := range ended {
		errs = append(errs, s.remove(id))
	}
	s.onChange()
	return errors.Join(errs...)
}

// Delete removes an ended activity, with its output; one not ended is
// left as it is, so that it can still be stopped. As with Clear, an
// activity whose meta.json could not be removed is kept.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	r, ok := s.activities[id]
	ended := ok && r.Status.Ended()
	s.mu.Unlock()
	if !ended {
		return nil
	}
	err := s.remove(id)
	s.onChange()
	return err
}

// remove removes an activity's files: its output first, then its meta.json,
// so that an activity whose output stays is still listed, and then what is
// left. Once its meta.json is removed, which Open would no longer list,
// the activity is no longer listed here either.
func (s *Store) remove(id string) error {
	dir := filepath.Join(s.dir, id)
	for _, name := range []string{"output.log", "meta.json"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	s.mu.Lock()
	delete(s.activities, id)
	s.mu.Unlock()
	return os.RemoveAll(dir)
}

// prune removes the oldest ended activities beyond keep, with s.mu held or
// before s is shared.
func (s *Store) prune() {
	if len(s.activities) <= keep {
		return
	}
	var ended []string
	for id, r := range s.activities {
		if r.Status.Ended() {
			ended = append(ended, id)
		}
	}
	slices.Sort(ended)
	for _, id := range ended[:max(0, min(len(ended), len(s.activities)-keep))] {
		os.RemoveAll(filepath.Join(s.dir, id))
		delete(s.activities, id)
	}
}

func (s *Store) save(r *Activity) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, r.ID, "meta.json")
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
