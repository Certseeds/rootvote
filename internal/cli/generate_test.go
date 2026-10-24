package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/Certseeds/rootvote/internal/ccadb"
	"github.com/Certseeds/rootvote/internal/manifest"
)

func fakeRec(t *testing.T, cn, country, recordType string) ccadb.Record {
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

func TestGenerate(t *testing.T) {
	records := []ccadb.Record{
		fakeRec(t, "CN Root", "China", ccadb.RecordRoot),
		fakeRec(t, "CN Inter", "China", ccadb.RecordIntermediate),
		fakeRec(t, "JP Root", "Japan", ccadb.RecordRoot),
	}
	deps := Deps{
		Version:  "test",
		Snapshot: "v1.20260101.000000",
		LoadData: func() ([]ccadb.Record, string, error) { return records, "v1.20260101.000000", nil },
	}
	out := filepath.Join(t.TempDir(), "blacklist")
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{"generate", "--countries", "CN", "--out", out}, &stdout, &stderr, deps)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	m, err := manifest.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Summary.Total != 2 || m.Summary.Roots != 1 || m.Summary.Intermediates != 1 {
		t.Fatalf("summary = %+v", m.Summary)
	}
	if m.Filter.CountryCodes[0] != "CN" {
		t.Fatalf("codes = %v", m.Filter.CountryCodes)
	}
}

func TestGenerateRootsOnly(t *testing.T) {
	records := []ccadb.Record{
		fakeRec(t, "CN Root", "China", ccadb.RecordRoot),
		fakeRec(t, "CN Inter", "China", ccadb.RecordIntermediate),
	}
	deps := Deps{Version: "test", LoadData: func() ([]ccadb.Record, string, error) {
		return records, "v1.20260101.000000", nil
	}}
	out := filepath.Join(t.TempDir(), "blacklist")
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{"generate", "--countries", "China", "--roots-only", "--out", out}, &stdout, &stderr, deps)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	m, err := manifest.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Summary.Total != 1 || m.Summary.Roots != 1 {
		t.Fatalf("summary = %+v", m.Summary)
	}
}

func TestCountriesJSON(t *testing.T) {
	records := []ccadb.Record{
		{SHA256: "a", Country: "China"},
		{SHA256: "b", Country: "China"},
		{SHA256: "c", Country: "Japan"},
	}
	deps := Deps{LoadData: func() ([]ccadb.Record, string, error) { return records, "v1.test", nil }}
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{"countries", "--json"}, &stdout, &stderr, deps)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"China"`)) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"Japan"`)) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}
