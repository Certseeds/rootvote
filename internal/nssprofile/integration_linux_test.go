//go:build linux && integration

package nssprofile

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Certseeds/rootvote/internal/nss"
)

func TestGeckoAndChromiumBlock(t *testing.T) {
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		t.Skip("需要 libnss3-tools")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	for _, app := range []App{AppFirefox, AppThunderbird, AppChromium} {
		t.Run(string(app), func(t *testing.T) {
			dataDir := t.TempDir()
			profileDir := filepath.Join(dataDir, "Profiles", "test")
			if err := os.MkdirAll(profileDir, 0o755); err != nil {
				t.Fatal(err)
			}
			nssDB := profileDir
			if app == AppChromium {
				nssDB = filepath.Join(dataDir, "nssdb")
				if err := os.MkdirAll(nssDB, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := exec.Command(certutil, "-N", "--empty-password", "-d", "sql:"+nssDB).CombinedOutput(); err != nil {
				t.Fatalf("certutil -N: %v: %s", err, out)
			}

			var profiles []Profile
			var warnings []string
			if app == AppChromium {
				profiles, warnings, err = DiscoverChromium(nssDB, nil)
			} else {
				profiles, warnings, err = DiscoverGecko(dataDir, app, []string{filepath.Join(nssDB, "cert9.db")})
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(warnings) != 0 || len(profiles) != 1 {
				t.Fatalf("profiles = %+v warnings = %v", profiles, warnings)
			}

			ct := nss.New(certutil)
			nick := "rootvote:integration"
			if err := ct.Add(context.Background(), profiles[0].Dir, nick, certPEM); err != nil {
				t.Fatal(err)
			}
			ok, err := ct.HasNickname(context.Background(), profiles[0].Dir, nick)
			if err != nil || !ok {
				t.Fatalf("HasNickname = %v, %v", ok, err)
			}
			if err := ct.Delete(context.Background(), profiles[0].Dir, nick); err != nil {
				t.Fatal(err)
			}
			ok, err = ct.HasNickname(context.Background(), profiles[0].Dir, nick)
			if err != nil || ok {
				t.Fatalf("HasNickname after delete = %v, %v", ok, err)
			}
		})
	}
}
