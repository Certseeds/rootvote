package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAddIsIdempotent(t *testing.T) {
	s := &State{Schema: 1}
	rec := Record{Type: "windows", Scope: "user", SHA256: "abc", AppliedAt: time.Now().UTC().Format(time.RFC3339)}
	if !s.Add(rec) {
		t.Fatal("first add returned false")
	}
	if s.Add(rec) {
		t.Fatal("duplicate add returned true")
	}
	if len(s.Applied) != 1 {
		t.Fatalf("applied = %d, want 1", len(s.Applied))
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := &State{Schema: 1}
	s.Add(Record{Type: "firefox", Profile: "C:/profiles/a", SHA256: "abc", Nickname: "rootvote:abc", AppliedAt: "2026-01-01T00:00:00Z"})
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Applied) != 1 || got.Applied[0].Nickname != "rootvote:abc" {
		t.Fatalf("got %+v", got)
	}
}

func TestRemoveMatching(t *testing.T) {
	s := &State{Schema: 1}
	s.Add(Record{Type: "windows", Scope: "user", SHA256: "a"})
	s.Add(Record{Type: "windows", Scope: "machine", SHA256: "b"})
	n := s.RemoveMatching(func(r Record) bool { return r.Scope == "user" })
	if n != 1 || len(s.Applied) != 1 || s.Applied[0].SHA256 != "b" {
		t.Fatalf("n = %d, applied = %+v", n, s.Applied)
	}
}

func TestLoadMissingReturnsEmpty(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != 1 || len(got.Applied) != 0 {
		t.Fatalf("got %+v", got)
	}
}
