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
	"github.com/Certseeds/rootvote/internal/firefox"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

func TestUndoRemovesOnlyStateRecords(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	statePath := filepath.Join(t.TempDir(), "state.json")
	store := &fakeStore{scope: platform.ScopeUser, certs: map[string]bool{}}
	deps := Deps{
		OpenStores:       func(scope platform.Scope) ([]platform.Store, error) { return []platform.Store{store}, nil },
		DiscoverProfiles: func() ([]firefox.Profile, []string, error) { return nil, nil, nil },
		IsRunning:        func(string) bool { return false },
		State:            &state.State{Schema: 1},
		Now:              time.Now,
		Out:              &bytes.Buffer{},
	}
	if _, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeUser, Browsers: []string{"system"},
		StatePath: statePath,
	}, deps); err != nil {
		t.Fatal(err)
	}
	if len(store.certs) != 1 {
		t.Fatalf("certs = %v", store.certs)
	}
	res, err := RunUndo(context.Background(), UndoOptions{
		ManifestDir: dir, Scope: platform.ScopeUser, StatePath: statePath,
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
	store := &fakeStore{scope: platform.ScopeUser, certs: map[string]bool{
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
		ManifestDir: dir, Scope: platform.ScopeUser, Force: true, DryRun: true,
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
