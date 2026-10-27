package history

import (
	"bytes"
	"testing"
)

func TestLifecycle(t *testing.T) {
	changes := 0
	s, err := Open(t.TempDir(), func() { changes++ })
	if err != nil {
		t.Fatal(err)
	}
	stops := 0
	rec, err := s.Begin("ns", []string{"echo", "hi"}, "/tmp", func() { stops++ })
	if err != nil {
		t.Fatal(err)
	}
	if r := s.List()[0]; r.Status != Authorizing || r.Namespace != "ns" {
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
	rec, _ := s.Begin("ns", []string{"sleep", "9"}, "/", func() { stopped = true })
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

func TestOpenMarksLeftoverRunsLost(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, func() {})
	authorizing, _ := s.Begin("ns", []string{"a"}, "/", func() {})
	running, _ := s.Begin("ns", []string{"b"}, "/", func() {})
	running.Authorized()
	denied, _ := s.Begin("ns", []string{"c"}, "/", func() {})
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
	rec, _ := s.Begin("ns", []string{"yes"}, "/", func() {})
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

func TestListAndPrune(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, func() {})
	running, _ := s.Begin("ns", []string{"first"}, "/", func() {})
	running.Authorized()
	for range keep + 5 {
		rec, _ := s.Begin("ns", []string{"x"}, "/", func() {})
		rec.Exited(0)
	}
	list := s.List()
	if len(list) != keep || list[0].ID != running.ID() {
		t.Fatalf("%d runs, first %+v", len(list), list[0])
	}
	for i := 2; i < len(list); i++ {
		if list[i-1].ID < list[i].ID {
			t.Fatal("ended runs not latest first")
		}
	}
	s2, _ := Open(dir, func() {})
	if n := len(s2.List()); n != keep {
		t.Fatalf("reopened with %d runs", n)
	}
}
