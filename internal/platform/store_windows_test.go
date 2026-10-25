//go:build windows

package platform

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func makeDER(t *testing.T) ([]byte, [20]byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "rootvote-test"},
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
	return der, sha1.Sum(der)
}

func TestUserDisallowedBlockUnblock(t *testing.T) {
	stores, err := Open(ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if len(stores) != 1 {
		t.Fatalf("stores = %d, want 1", len(stores))
	}
	s := stores[0]
	defer s.Close()

	der, sha := makeDER(t)
	_ = s.Unblock(sha)

	br, err := s.Block(der)
	if err != nil {
		t.Fatal(err)
	}
	if !br.Changed {
		t.Fatal("want Changed=true on first block")
	}
	br, err = s.Block(der)
	if err != nil {
		t.Fatal(err)
	}
	if br.Changed {
		t.Fatal("want Changed=false on duplicate block")
	}
	ok, err := s.Blocked(sha)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("certificate not found after block")
	}
	if err := s.Unblock(sha); err != nil {
		t.Fatal(err)
	}
	ok, err = s.Blocked(sha)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("certificate still present after unblock")
	}
}
