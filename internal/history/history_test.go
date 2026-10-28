package history

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLifecycle(t *testing.T) {
	changes := 0
	s, err := Open(t.TempDir(), func() { changes++ })
	if err != nil {
		t.Fatal(err)
	}
	stops := 0
	rec, err := s.Begin("dev", []string{"echo", "hi"}, "/tmp", func() { stops++ })
	if err != nil {
		t.Fatal(err)
	}
	if r := s.List()[0]; r.Status != Authorizing || r.Vault != "dev" {
		t.Fatalf("begun: %+v", r)
	}
	rec.Authorized()
	rec.Started(42)
	rec.Write([]byte("hi\n"))
	if r := s.List()[0]; r.Status != Running || r.PGID != 42 || s.Running() != 1 {
		t.Fatalf("running: %+v", r)
	}
	rec.Exited(0)
	r := s.List()[0]
	if r.Status != Exited || r.ExitCode != 0 || r.EndedAt.IsZero() || s.Running() != 0 {
		t.Fatalf("exited: %+v", r)
	}
	if out, _ := s.Output(r.ID); string(out) != "hi\n" {
		t.Fatalf("output %q", out)
	}
	// Stopping one ended does nothing.
	s.Stop(r.ID)
	if stops != 0 || changes == 0 {
		t.Fatalf("stops %d, changes %d", stops, changes)
	}
}

func TestStoppedByUser(t *testing.T) {
	s, _ := Open(t.TempDir(), func() {})
	stopped := false
	rec, _ := s.Begin("dev", []string{"sleep", "9"}, "/", func() { stopped = true })
	rec.Authorized()
	s.Stop(rec.ID())
	if !stopped {
		t.Fatal("stop not called")
	}
	rec.Exited(143)
	if r := s.List()[0]; r.Status != Stopped || r.ExitCode != 143 {
		t.Fatalf("got %+v", r)
	}
}

func TestOpenMarksLeftoverActivitiesLost(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, func() {})
	authorizing, _ := s.Begin("dev", []string{"a"}, "/", func() {})
	running, _ := s.Begin("dev", []string{"b"}, "/", func() {})
	running.Authorized()
	denied, _ := s.Begin("dev", []string{"c"}, "/", func() {})
	denied.End(Denied)

	s2, err := Open(dir, func() {})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Status{}
	for _, r := range s2.List() {
		got[r.ID] = r.Status
	}
	if got[authorizing.ID()] != Lost || got[running.ID()] != Lost || got[denied.ID()] != Denied {
		t.Fatalf("got %v", got)
	}
}

func TestOutputKeepsItsEnd(t *testing.T) {
	s, _ := Open(t.TempDir(), func() {})
	rec, _ := s.Begin("dev", []string{"yes"}, "/", func() {})
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for range 4 {
		rec.Write(chunk)
	}
	rec.Write([]byte("the end"))
	rec.Exited(0)
	out, _ := s.Output(rec.ID())
	if len(out) > maxOutput || !bytes.HasSuffix(out, []byte("xthe end")) {
		t.Fatalf("output of %d bytes ending %q", len(out), out[max(0, len(out)-10):])
	}
	if !s.List()[0].Truncated {
		t.Fatal("not marked truncated")
	}
}

func TestClearKeepsActivitiesNotEnded(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, func() {})
	running, _ := s.Begin("dev", []string{"serve"}, "/", func() {})
	running.Authorized()
	for range 3 {
		rec, _ := s.Begin("dev", []string{"x"}, "/", func() {})
		rec.Exited(0)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if list := s.List(); len(list) != 1 || list[0].ID != running.ID() {
		t.Fatalf("left %+v", list)
	}
	running.Exited(0)
	s2, _ := Open(dir, func() {})
	if list := s2.List(); len(list) != 1 || list[0].ID != running.ID() {
		t.Fatalf("reopened with %+v", list)
	}
}

func TestClearKeepsActivitiesNotRemoved(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, func() {})
	stuck, _ := s.Begin("dev", []string{"stuck"}, "/", func() {})
	stuck.Exited(0)
	gone, _ := s.Begin("dev", []string{"gone"}, "/", func() {})
	gone.Exited(0)
	// Without write permission, its files cannot be removed.
	locked := filepath.Join(dir, stuck.ID())
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	if err := s.Clear(); err == nil {
		t.Fatal("no error for the activity not removed")
	}
	if list := s.List(); len(list) != 1 || list[0].ID != stuck.ID() {
		t.Fatalf("left %+v", list)
	}
	s2, _ := Open(dir, func() {})
	if list := s2.List(); len(list) != 1 || list[0].ID != stuck.ID() {
		t.Fatalf("reopened with %+v", list)
	}
}

// An activity whose output cannot be removed keeps its meta.json, so that it is
// still listed, now and on the next Open, rather than left on the disk
// unseen.
func TestClearKeepsActivitiesWithOutputNotRemoved(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, func() {})
	rec, _ := s.Begin("dev", []string{"stuck"}, "/", func() {})
	rec.Exited(0)
	// Its output, a directory whose file cannot be removed, which
	// RemoveAll would reach after meta.json.
	out := filepath.Join(dir, rec.ID(), "output.log")
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "part"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(out, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(out, 0o700) })
	if err := s.Clear(); err == nil {
		t.Fatal("no error for the output not removed")
	}
	if _, err := os.Stat(filepath.Join(dir, rec.ID(), "meta.json")); err != nil {
		t.Fatalf("meta.json: %v", err)
	}
	s2, _ := Open(dir, func() {})
	if list := s2.List(); len(list) != 1 || list[0].ID != rec.ID() {
		t.Fatalf("reopened with %+v", list)
	}
}

func TestListAndPrune(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, func() {})
	running, _ := s.Begin("dev", []string{"first"}, "/", func() {})
	running.Authorized()
	for range keep + 5 {
		rec, _ := s.Begin("dev", []string{"x"}, "/", func() {})
		rec.Exited(0)
	}
	list := s.List()
	if len(list) != keep || list[0].ID != running.ID() {
		t.Fatalf("%d activities, first %+v", len(list), list[0])
	}
	for i := 2; i < len(list); i++ {
		if list[i-1].ID < list[i].ID {
			t.Fatal("ended activities not latest first")
		}
	}
	s2, _ := Open(dir, func() {})
	if n := len(s2.List()); n != keep {
		t.Fatalf("reopened with %d activities", n)
	}
}
