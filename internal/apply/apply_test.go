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
	"strings"
	"testing"
	"time"

	"github.com/Certseeds/rootvote/internal/ccadb"
	"github.com/Certseeds/rootvote/internal/exitcode"
	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/nssprofile"
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

func TestRunAddsToSystemStore(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	store := &fakeStore{scope: platform.ScopeMachine, certs: map[string]bool{}}
	deps := Deps{
		OpenStores: func(scope platform.Scope) ([]platform.Store, error) {
			return []platform.Store{store}, nil
		},
		DiscoverProfiles: func(nssprofile.App, []string) ([]nssprofile.Profile, []string, error) {
			return nil, nil, nil
		},
		IsRunning: func(nssprofile.Profile) bool { return false },
		State:     &state.State{Schema: 1},
		Now:       func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		Out:       &bytes.Buffer{},
	}
	res, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeMachine, Targets: []string{TargetSystem},
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v", res)
	}
	if len(res.Targets) != 1 || res.Targets[0].Name != "system:machine" || res.Targets[0].Added != 1 {
		t.Fatalf("targets = %+v", res.Targets)
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
	store := &fakeStore{scope: platform.ScopeMachine, certs: map[string]bool{pre: true}}
	deps := Deps{
		OpenStores: func(platform.Scope) ([]platform.Store, error) {
			return []platform.Store{store}, nil
		},
		DiscoverProfiles: func(nssprofile.App, []string) ([]nssprofile.Profile, []string, error) {
			return nil, nil, nil
		},
		IsRunning: func(nssprofile.Profile) bool { return false },
		State:     &state.State{Schema: 1},
		Now:       time.Now,
		Out:       &bytes.Buffer{},
	}
	res, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeMachine, Targets: []string{TargetSystem},
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

func TestRunAppRunning(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	deps := Deps{
		OpenStores: func(platform.Scope) ([]platform.Store, error) { return nil, nil },
		DiscoverProfiles: func(app nssprofile.App, _ []string) ([]nssprofile.Profile, []string, error) {
			return []nssprofile.Profile{{App: app, Name: "default", Dir: "/profile", CertDB: "/profile/cert9.db"}}, nil, nil
		},
		IsRunning: func(nssprofile.Profile) bool { return true },
		Certutil:  nss.New("certutil"),
		State:     &state.State{Schema: 1},
		Now:       time.Now,
		Out:       &bytes.Buffer{},
	}
	_, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeUser, Targets: []string{TargetThunderbird},
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	var e *Error
	if !errors.As(err, &e) || e.Code != exitcode.AppRunning {
		t.Fatalf("err = %v, want exit code %d", err, exitcode.AppRunning)
	}
}

type fakeNSS struct {
	list   []byte
	export map[string][]byte
}

func (f *fakeNSS) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-L -n") && strings.Contains(joined, "-a") {
		for i, a := range args {
			if a == "-n" && i+1 < len(args) {
				return f.export[args[i+1]], nil, nil
			}
		}
	}
	if strings.Contains(joined, "-L") {
		return f.list, nil, nil
	}
	return nil, nil, nil
}

func makeRoot(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func makeIntermediate(t *testing.T, root *x509.Certificate, rootKey *rsa.PrivateKey, serial *big.Int, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestIsProhibited(t *testing.T) {
	if !isProhibited("p,p,p") {
		t.Fatal("p,p,p should be prohibited")
	}
	if isProhibited(",,") {
		t.Fatal(",, should not be prohibited")
	}
	if isProhibited("C,C,C") {
		t.Fatal("C,C,C should not be prohibited")
	}
}

func TestFindExistingByIssuerSerial(t *testing.T) {
	root, rootKey := makeRoot(t)
	target := makeIntermediate(t, root, rootKey, big.NewInt(42), "Target Intermediate")
	existing := makeIntermediate(t, root, rootKey, big.NewInt(42), "Existing Intermediate")
	existingPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: existing})
	fake := &fakeNSS{
		list:   []byte("Certificate Nickname Trust Attributes\n\nrootvote:old p,p,p\n"),
		export: map[string][]byte{"rootvote:old": existingPEM},
	}
	c := &nss.Certutil{Path: "certutil", Exec: fake}
	nick, trust, found, err := findExistingProfileByIssuerSerial(context.Background(), c, "profile", target)
	if err != nil {
		t.Fatal(err)
	}
	if !found || nick != "rootvote:old" || trust != "p,p,p" {
		t.Fatalf("found=%v nick=%q trust=%q", found, nick, trust)
	}
}

type fakeNSSStore struct {
	entries map[string]bool
}

func (f *fakeNSSStore) Run(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
	joined := strings.Join(args, " ")
	nick := ""
	for i, a := range args {
		if a == "-n" && i+1 < len(args) {
			nick = args[i+1]
		}
	}
	switch {
	case strings.Contains(joined, "-A"):
		f.entries[nick] = true
		return nil, nil, nil
	case strings.Contains(joined, "-D"):
		delete(f.entries, nick)
		return nil, nil, nil
	case strings.Contains(joined, "-M"):
		return nil, nil, nil
	case strings.Contains(joined, "-L") && nick != "":
		if nick == "__rootvote_probe__" {
			return nil, []byte("not found"), errors.New("exit 1")
		}
		if f.entries[nick] || f.entries["NSS Certificate DB:"+nick] {
			return []byte("cert"), nil, nil
		}
		return nil, []byte("not found"), errors.New("exit 1")
	default:
		return nil, nil, nil
	}
}

func TestRunThunderbirdProfile(t *testing.T) {
	rec := makeRecord(t, "China")
	dir := makeManifest(t, []ccadb.Record{rec})
	fake := &fakeNSSStore{entries: map[string]bool{}}
	profile := nssprofile.Profile{
		App: nssprofile.AppThunderbird, Name: "default",
		Dir: "/data/thunderbird", CertDB: "/data/thunderbird/cert9.db",
	}
	deps := Deps{
		OpenStores: func(platform.Scope) ([]platform.Store, error) { return nil, nil },
		DiscoverProfiles: func(app nssprofile.App, _ []string) ([]nssprofile.Profile, []string, error) {
			if app != nssprofile.AppThunderbird {
				t.Fatalf("app = %q", app)
			}
			return []nssprofile.Profile{profile}, nil, nil
		},
		IsRunning: func(nssprofile.Profile) bool { return false },
		Certutil:  &nss.Certutil{Path: "certutil", Exec: fake},
		State:     &state.State{Schema: 1},
		Now:       time.Now,
		Out:       &bytes.Buffer{},
	}
	res, err := Run(context.Background(), Options{
		ManifestDir: dir, Scope: platform.ScopeUser, Targets: []string{TargetThunderbird},
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v", res)
	}
	if len(res.Targets) != 1 || res.Targets[0].Name != "thunderbird:/data/thunderbird" {
		t.Fatalf("targets = %+v", res.Targets)
	}
	if len(deps.State.Applied) != 1 || deps.State.Applied[0].Type != "thunderbird" {
		t.Fatalf("state = %+v", deps.State.Applied)
	}
}

func TestRunUnknownTargetIsUsage(t *testing.T) {
	deps := Deps{
		State: &state.State{Schema: 1},
		Now:   time.Now,
		Out:   &bytes.Buffer{},
	}
	_, err := Run(context.Background(), Options{
		ManifestDir: t.TempDir(), Scope: platform.ScopeUser, Targets: []string{"safari"},
		StatePath: filepath.Join(t.TempDir(), "state.json"),
	}, deps)
	var e *Error
	if !errors.As(err, &e) || e.Code != exitcode.Usage {
		t.Fatalf("err = %v, want usage", err)
	}
}
