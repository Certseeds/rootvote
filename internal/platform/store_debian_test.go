//go:build linux

package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
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
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func testDebianPaths(t *testing.T) debianPaths {
	t.Helper()
	root := t.TempDir()
	return debianPaths{
		Conf:        filepath.Join(root, "ca-certificates.conf"),
		Bundle:      filepath.Join(root, "ca-certificates.crt"),
		PackageRoot: filepath.Join(root, "usr-share"),
		LocalRoot:   filepath.Join(root, "usr-local"),
		StateDir:    filepath.Join(root, "state"),
		Index:       filepath.Join(root, "state", "blocked.json"),
		BackupDir:   filepath.Join(root, "state", "backup"),
		Lock:        filepath.Join(root, "state", "lock"),
	}
}

func fakeUpdate(t *testing.T, calls *int, fail bool) commandRunner {
	t.Helper()
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "update-ca-certificates" || len(args) != 1 || args[0] != "--fresh" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		*calls++
		if fail {
			return []byte("boom"), errors.New("exit 1")
		}
		return nil, nil
	}
}

func TestDebianBlockPackageCert(t *testing.T) {
	p := testDebianPaths(t)
	der, certPEM := testCert(t, "Package CA")
	rel := "mozilla/test-ca.crt"
	if err := os.MkdirAll(filepath.Join(p.PackageRoot, "mozilla"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.PackageRoot, rel), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	original := "mozilla/other.crt\n" + rel + "\n"
	if err := os.WriteFile(p.Conf, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Bundle, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := openDebian(p, fakeUpdate(t, &calls, false), "update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sum := sha1.Sum(der)
	br, err := s.Block(der)
	if err != nil {
		t.Fatal(err)
	}
	if !br.Changed || br.BackupPath != "" {
		t.Fatalf("block result = %+v", br)
	}
	if calls != 1 {
		t.Fatalf("update calls = %d", calls)
	}
	blocked, err := s.Blocked(sum)
	if err != nil || !blocked {
		t.Fatalf("blocked = %v, %v", blocked, err)
	}
	conf, err := os.ReadFile(p.Conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "!mozilla/test-ca.crt") {
		t.Fatalf("conf = %s", conf)
	}
	if err := s.Unblock(sum); err != nil {
		t.Fatal(err)
	}
	conf, err = os.ReadFile(p.Conf)
	if err != nil {
		t.Fatal(err)
	}
	if string(conf) != original {
		t.Fatalf("conf after unblock = %q, want %q", conf, original)
	}
	blocked, err = s.Blocked(sum)
	if err != nil || blocked {
		t.Fatalf("blocked after unblock = %v, %v", blocked, err)
	}
}

func TestDebianBlockNotInBundle(t *testing.T) {
	p := testDebianPaths(t)
	der, _ := testCert(t, "Not In Bundle")
	if err := os.WriteFile(p.Conf, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Bundle, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := openDebian(p, fakeUpdate(t, &calls, false), "update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	br, err := s.Block(der)
	if err != nil {
		t.Fatal(err)
	}
	if br.Changed || calls != 0 {
		t.Fatalf("result = %+v calls = %d", br, calls)
	}
}

func TestDebianBlockLocalCert(t *testing.T) {
	p := testDebianPaths(t)
	der, certPEM := testCert(t, "Local CA")
	local := filepath.Join(p.LocalRoot, "test.crt")
	if err := os.MkdirAll(p.LocalRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(local, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Conf, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Bundle, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := openDebian(p, fakeUpdate(t, &calls, false), "update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sum := sha1.Sum(der)
	sha256sum := sha256.Sum256(der)
	wantBackup := filepath.Join(p.BackupDir, hex.EncodeToString(sha256sum[:])+".crt")
	br, err := s.Block(der)
	if err != nil {
		t.Fatal(err)
	}
	if !br.Changed || br.BackupPath != wantBackup {
		t.Fatalf("block result = %+v", br)
	}
	if _, err := os.Stat(local); !os.IsNotExist(err) {
		t.Fatalf("local cert still present: %v", err)
	}
	if _, err := os.Stat(wantBackup); err != nil {
		t.Fatal(err)
	}
	if err := s.Unblock(sum); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(local); err != nil {
		t.Fatalf("local cert not restored: %v", err)
	}
	if _, err := os.Stat(wantBackup); !os.IsNotExist(err) {
		t.Fatalf("backup still present: %v", err)
	}
}

func TestDebianBlockRollsBackOnUpdateFailure(t *testing.T) {
	p := testDebianPaths(t)
	der, certPEM := testCert(t, "Broken Update")
	rel := "mozilla/broken.crt"
	if err := os.MkdirAll(filepath.Join(p.PackageRoot, "mozilla"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.PackageRoot, rel), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	original := rel + "\n"
	if err := os.WriteFile(p.Conf, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Bundle, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := openDebian(p, fakeUpdate(t, &calls, true), "update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.Block(der); err == nil {
		t.Fatal("want update failure")
	}
	conf, err := os.ReadFile(p.Conf)
	if err != nil {
		t.Fatal(err)
	}
	if string(conf) != original {
		t.Fatalf("conf = %q, want %q", conf, original)
	}
	blocked, err := s.Blocked(sha1.Sum(der))
	if err != nil || blocked {
		t.Fatalf("blocked = %v, %v", blocked, err)
	}
	if _, err := os.Stat(filepath.Join(p.PackageRoot, rel)); err != nil {
		t.Fatalf("package cert removed: %v", err)
	}
}

func TestDebianIndexPersistsAndLock(t *testing.T) {
	p := testDebianPaths(t)
	der, certPEM := testCert(t, "Persist CA")
	rel := "mozilla/persist.crt"
	if err := os.MkdirAll(filepath.Join(p.PackageRoot, "mozilla"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.PackageRoot, rel), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Conf, []byte(rel+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Bundle, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := openDebian(p, fakeUpdate(t, &calls, false), "update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openDebian(p, fakeUpdate(t, &calls, false), "update-ca-certificates"); err == nil {
		s.Close()
		t.Fatal("second open should fail on lock")
	}
	if _, err := s.Block(der); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := openDebian(p, fakeUpdate(t, &calls, false), "update-ca-certificates")
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	blocked, err := s2.Blocked(sha1.Sum(der))
	if err != nil || !blocked {
		t.Fatalf("blocked after reopen = %v, %v", blocked, err)
	}
}
