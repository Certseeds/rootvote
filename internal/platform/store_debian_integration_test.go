//go:build linux && integration

package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDebianSystemBlockUnblock(t *testing.T) {
	if os.Getenv("ROOTVOTE_INTEGRATION") != "1" {
		t.Skip("set ROOTVOTE_INTEGRATION=1 to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("需要 root")
	}
	if _, err := exec.LookPath("update-ca-certificates"); err != nil {
		t.Skip("需要 ca-certificates")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "rootvote integration"},
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
	path := fmt.Sprintf("/usr/local/share/ca-certificates/rootvote-integration-%d.crt", os.Getpid())
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if out, err := exec.Command("update-ca-certificates", "--fresh").CombinedOutput(); err != nil {
		t.Fatalf("update-ca-certificates: %v: %s", err, out)
	}

	stores, err := Open(ScopeMachine)
	if err != nil {
		t.Fatal(err)
	}
	s := stores[0]
	defer s.Close()
	sum := sha1.Sum(der)
	_ = s.Unblock(sum)

	br, err := s.Block(der)
	if err != nil {
		t.Fatal(err)
	}
	if !br.Changed {
		t.Fatal("want Changed=true")
	}
	blocked, err := s.Blocked(sum)
	if err != nil || !blocked {
		t.Fatalf("blocked = %v, %v", blocked, err)
	}
	if err := s.Unblock(sum); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("certificate not restored: %v", err)
	}
	blocked, err = s.Blocked(sum)
	if err != nil || blocked {
		t.Fatalf("blocked after unblock = %v, %v", blocked, err)
	}
}
