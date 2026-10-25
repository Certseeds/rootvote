package apply

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/Certseeds/rootvote/internal/ccadb"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/nssprofile"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

func TestUndoRemovesOnlyStateRecords(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	statePath := filepath.Join(t.TempDir(), "state.json")
	store := &fakeStore{scope: platform.ScopeMachine, certs: map[string]bool{}}
	deps := Deps{
		OpenStores: func(scope platform.Scope) ([]platform.Store, error) { return []platform.Store{store}, nil },
		DiscoverProfiles: func(nssprofile.App, []string) ([]nssprofile.Profile, []string, error) {
			return nil, nil, nil
		},
		IsRunning: func(nssprofile.Profile) bool { return false },
		State:     &state.State{Schema: 1},
		Now:       time.Now,
		Out:       &bytes.Buffer{},
	}
	if _, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeMachine, Targets: []string{TargetSystem},
		StatePath: statePath,
	}, deps); err != nil {
		t.Fatal(err)
	}
	if len(store.certs) != 1 {
		t.Fatalf("certs = %v", store.certs)
	}
	res, err := RunUndo(context.Background(), UndoOptions{
		ManifestDir: dir, Scope: platform.ScopeMachine, Targets: []string{TargetSystem},
		StatePath: statePath,
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || len(store.certs) != 0 {
		t.Fatalf("result = %+v, certs = %v", res, store.certs)
	}
}

func TestForceUndoDryRunCountsPresent(t *testing.T) {
	rec1 := makeRecord(t, "China")
	rec2 := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec1, rec2})
	der1, _ := pem.Decode([]byte(rec1.PEM))
	sum1 := sha1.Sum(der1.Bytes)
	store := &fakeStore{scope: platform.ScopeMachine, certs: map[string]bool{
		hex.EncodeToString(sum1[:]): true,
	}}
	deps := Deps{
		OpenStores: func(scope platform.Scope) ([]platform.Store, error) {
			return []platform.Store{store}, nil
		},
		State: &state.State{Schema: 1},
		Now:   time.Now,
		Out:   &bytes.Buffer{},
	}
	res, err := RunUndo(context.Background(), UndoOptions{
		ManifestDir: dir, Scope: platform.ScopeMachine, Targets: []string{TargetSystem},
		Force: true, DryRun: true,
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 {
		t.Fatalf("added = %d, want 1", res.Added)
	}
	if len(store.certs) != 1 {
		t.Fatalf("store changed: %v", store.certs)
	}
}

func TestForceUndoRemovesNSSNickname(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	fake := &fakeNSSStore{entries: map[string]bool{
		"rootvote:" + rec.SHA256[:16]: true,
	}}
	profile := nssprofile.Profile{
		App: nssprofile.AppThunderbird, Name: "default",
		Dir: "/data/thunderbird", CertDB: "/data/thunderbird/cert9.db",
	}
	deps := Deps{
		OpenStores: func(platform.Scope) ([]platform.Store, error) { return nil, nil },
		DiscoverProfiles: func(nssprofile.App, []string) ([]nssprofile.Profile, []string, error) {
			return []nssprofile.Profile{profile}, nil, nil
		},
		IsRunning: func(nssprofile.Profile) bool { return false },
		Certutil:  &nss.Certutil{Path: "certutil", Exec: fake},
		State:     &state.State{Schema: 1},
		Now:       time.Now,
		Out:       &bytes.Buffer{},
	}
	res, err := RunUndo(context.Background(), UndoOptions{
		ManifestDir: dir, Scope: platform.ScopeUser,
		Targets: []string{TargetThunderbird}, Force: true,
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 {
		t.Fatalf("result = %+v", res)
	}
	if fake.entries["rootvote:"+rec.SHA256[:16]] {
		t.Fatal("nickname still present")
	}
}
