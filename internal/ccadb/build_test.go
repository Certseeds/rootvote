package ccadb

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeTestCert(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	sha := hex.EncodeToString(sum[:])
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return sha, string(pemBytes)
}

func writeCSV(t *testing.T, path string, rows [][]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.WriteAll(rows); err != nil {
		t.Fatal(err)
	}
}

func TestBuildFromDir(t *testing.T) {
	dir := t.TempDir()
	sha1, pem1 := makeTestCert(t, "Root One")
	sha2, pem2 := makeTestCert(t, "Intermediate Two")

	writeCSV(t, filepath.Join(dir, "data", "AllCertificateRecordsCSVFormatV5"), [][]string{
		{"CA Owner", "Certificate Name", "Certificate Record Type", "SHA-256 Fingerprint", "TLS Capable", "Status of Root Cert", "Country"},
		{"Owner One", "Root One", RecordRoot, sha1, "True", "Included", "China"},
		{"Owner Two", "Intermediate Two", RecordIntermediate, sha2, "False", "Removed", "Japan"},
	})
	writeCSV(t, filepath.Join(dir, "cmd", "ski_spki", "data", "AllCertificatePEMsCSVFormat_NotBeforeYear_2020"), [][]string{
		{"SHA-256 Fingerprint", "X.509 Certificate (PEM)"},
		{sha1, pem1},
		{sha2, pem2},
	})

	out := filepath.Join(dir, "out")
	res, err := BuildFromDir(dir, out, "v1.20200101.000000", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 || res.Snapshot != "v1.20200101.000000" {
		t.Fatalf("result = %+v", res)
	}

	records, err := LoadFile(filepath.Join(out, "data.zst"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d, want 2", len(records))
	}
	bySHA := make(map[string]Record, len(records))
	for _, r := range records {
		bySHA[r.SHA256] = r
	}
	if bySHA[sha1].Country != "China" {
		t.Fatalf("record for sha1 = %+v", bySHA[sha1])
	}
	if bySHA[sha2].Country != "Japan" {
		t.Fatalf("record for sha2 = %+v", bySHA[sha2])
	}
}

func TestBuildFromDirMissingPEM(t *testing.T) {
	dir := t.TempDir()
	writeCSV(t, filepath.Join(dir, "data", "AllCertificateRecordsCSVFormatV5"), [][]string{
		{"CA Owner", "Certificate Name", "Certificate Record Type", "SHA-256 Fingerprint", "TLS Capable", "Status of Root Cert", "Country"},
		{"Owner", "Missing", RecordRoot, "deadbeef", "True", "Included", "China"},
	})
	writeCSV(t, filepath.Join(dir, "cmd", "ski_spki", "data", "AllCertificatePEMsCSVFormat_NotBeforeYear_2020"), [][]string{
		{"SHA-256 Fingerprint", "X.509 Certificate (PEM)"},
	})
	if _, err := BuildFromDir(dir, filepath.Join(dir, "out"), "v1.test", nil); err != nil {
		t.Fatal(err)
	}
}
