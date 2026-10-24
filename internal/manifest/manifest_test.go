package manifest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Certseeds/rootvote/internal/ccadb"
)

func testRecord(t *testing.T, cn, country, recordType string) ccadb.Record {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
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
		Owner:      "Owner " + cn,
		Country:    country,
		CertName:   cn,
		RecordType: recordType,
		TLSCapable: true,
		Status:     "Included",
		PEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

func TestSnapshotTime(t *testing.T) {
	got, err := SnapshotTime("v1.20261023.91613")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 10, 23, 9, 16, 13, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err := SnapshotTime("bad"); err == nil {
		t.Fatal("want error")
	}
}

func TestBuildWriteReadVerify(t *testing.T) {
	records := []ccadb.Record{
		testRecord(t, "Root A", "China", ccadb.RecordRoot),
		testRecord(t, "Inter B", "China", ccadb.RecordIntermediate),
	}
	filter := Filter{
		Countries:    []string{"China"},
		CountryCodes: []string{"CN"},
		RecordTypes:  []string{ccadb.RecordRoot, ccadb.RecordIntermediate},
	}
	m, certs, err := Build(records, "v1.20260101.000000", "rootvote test", filter)
	if err != nil {
		t.Fatal(err)
	}
	if m.Summary.Total != 2 || m.Summary.Roots != 1 || m.Summary.Intermediates != 1 {
		t.Fatalf("summary = %+v", m.Summary)
	}
	dir := filepath.Join(t.TempDir(), "blacklist")
	if err := Write(dir, m, certs); err != nil {
		t.Fatal(err)
	}
	got, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(got.Entries))
	}
	der, err := LoadCerts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(der) != 2 {
		t.Fatalf("certs = %d, want 2", len(der))
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	rec := testRecord(t, "Root A", "China", ccadb.RecordRoot)
	m, certs, err := Build([]ccadb.Record{rec}, "v1.20260101.000000", "rootvote test", Filter{
		Countries:    []string{"China"},
		CountryCodes: []string{"CN"},
		RecordTypes:  []string{ccadb.RecordRoot},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "blacklist")
	if err := Write(dir, m, certs); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filepath.FromSlash(CertPath(rec.SHA256)))
	if err := os.WriteFile(path, []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err == nil {
		t.Fatal("want verification error")
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	rec := testRecord(t, "Root A", "China", ccadb.RecordRoot)
	m, _, err := Build([]ccadb.Record{rec}, "v1.20260101.000000", "rootvote test", Filter{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("marshal output is not deterministic")
	}
}
