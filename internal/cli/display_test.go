package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Certseeds/rootvote/internal/ccadb"
	"github.com/Certseeds/rootvote/internal/manifest"
)

func TestDisplayManifest(t *testing.T) {
	rec := fakeRec(t, "Root A", "China", ccadb.RecordRoot)
	m, certs, err := manifest.Build([]ccadb.Record{rec}, "v1.20260101.000000", "rootvote test", manifest.Filter{
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
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{"display", "--manifest", dir}, &stdout, &stderr, Deps{})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("Root A")) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("China")) {
		t.Fatalf("stdout = %s", stdout.String())
	}
}

func TestDisplayVerifyRejectsTampering(t *testing.T) {
	rec := fakeRec(t, "Root A", "China", ccadb.RecordRoot)
	m, certs, err := manifest.Build([]ccadb.Record{rec}, "v1.20260101.000000", "rootvote test", manifest.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "blacklist")
	if err := manifest.Write(dir, m, certs); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, filepath.FromSlash(manifest.CertPath(rec.SHA256)))
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{"display", "--manifest", dir, "--verify"}, &stdout, &stderr, Deps{})
	if code != ExitManifestInvalid {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, ExitManifestInvalid, stderr.String())
	}
}
