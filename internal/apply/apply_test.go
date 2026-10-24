package apply

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/Certseeds/rootvote/internal/ccadb"
	"github.com/Certseeds/rootvote/internal/exitcode"
	"github.com/Certseeds/rootvote/internal/firefox"
	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

type fakeStore struct {
	scope platform.Scope
	certs map[string]bool
}

func (f *fakeStore) Scope() platform.Scope { return f.scope }

func (f *fakeStore) Contains(sha1 [20]byte) (bool, error) {
	return f.certs[hex.EncodeToString(sha1[:])], nil
}

func (f *fakeStore) Add(der []byte) error {
	sum := sha1.Sum(der)
	f.certs[hex.EncodeToString(sum[:])] = true
	return nil
}

func (f *fakeStore) Remove(sha1 [20]byte) error {
	delete(f.certs, hex.EncodeToString(sha1[:]))
	return nil
}

func (f *fakeStore) Close() error { return nil }

func makeRecord(t *testing.T, country string) ccadb.Record {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rootvote-test"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return ccadb.Record{
		SHA256:     hex.EncodeToString(sum[:]),
		Owner:      "Owner",
		Country:    country,
		CertName:   "rootvote-test",
		RecordType: ccadb.RecordRoot,
		TLSCapable: true,
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

func makeManifest(t *testing.T, records []ccadb.Record) string {
	t.Helper()
	m, certs, err := manifest.Build(records, "v1.20260101.000000", "rootvote test", manifest.Filter{
		Countries:    []string{"China"},
		CountryCodes: []string{"CN"},
		RecordTypes:  []string{ccadb.RecordRoot},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "blacklist")
	if err := manifest.Write(dir, m, certs); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunAddsToUserStore(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	store := &fakeStore{scope: platform.ScopeUser, certs: map[string]bool{}}
	deps := Deps{
		OpenStores: func(scope platform.Scope) ([]platform.Store, error) {
			return []platform.Store{store}, nil
		},
		DiscoverProfiles: func() ([]firefox.Profile, []string, error) { return nil, nil, nil },
		IsRunning:        func(string) bool { return false },
		State:            &state.State{Schema: 1},
		Now:              func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		Out:              &bytes.Buffer{},
	}
	res, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeUser, Browsers: []string{"system"},
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v", res)
	}
	if len(deps.State.Applied) != 1 {
		t.Fatalf("state = %+v", deps.State.Applied)
	}
}

func TestRunSkipsPreExisting(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	der, _ := pem.Decode([]byte(rec.PEM))
	sha1sum := sha1.Sum(der.Bytes)
	pre := hex.EncodeToString(sha1sum[:])
	store := &fakeStore{scope: platform.ScopeUser, certs: map[string]bool{pre: true}}
	deps := Deps{
		OpenStores:       func(scope platform.Scope) ([]platform.Store, error) { return []platform.Store{store}, nil },
		DiscoverProfiles: func() ([]firefox.Profile, []string, error) { return nil, nil, nil },
		IsRunning:        func(string) bool { return false },
		State:            &state.State{Schema: 1},
		Now:              time.Now,
		Out:              &bytes.Buffer{},
	}
	res, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeUser, Browsers: []string{"system"},
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 1 || res.Added != 0 {
		t.Fatalf("result = %+v", res)
	}
	if len(deps.State.Applied) != 0 {
		t.Fatalf("state should be empty, got %+v", deps.State.Applied)
	}
}

func TestRunFirefoxRunning(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	deps := Deps{
		OpenStores: func(scope platform.Scope) ([]platform.Store, error) { return nil, nil },
		DiscoverProfiles: func() ([]firefox.Profile, []string, error) {
			return []firefox.Profile{{Name: "default", Dir: "C:/profile", CertDB: "C:/profile/cert9.db"}}, nil, nil
		},
		IsRunning: func(string) bool { return true },
		Certutil:  nss.New("certutil"),
		State:     &state.State{Schema: 1},
		Now:       time.Now,
		Out:       &bytes.Buffer{},
	}
	_, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeUser, Browsers: []string{"firefox"},
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	var e *Error
	if !errors.As(err, &e) || e.Code != exitcode.FirefoxRunning {
		t.Fatalf("err = %v, want exit code %d", err, exitcode.FirefoxRunning)
	}
}
