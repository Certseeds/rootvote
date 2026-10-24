package nssfetch

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func makePackage(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseLock(t *testing.T) {
	lock := strings.Join([]string{
		"[[package]]",
		`url = "https://example.com/a.pkg.tar.zst"`,
		`sha256 = "abc"`,
		"",
		"[[package]]",
		`url = "https://example.com/b.pkg.tar.zst"`,
		`sha256 = "def"`,
	}, string(rune(10)))
	pkgs, err := ParseLock(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].URL != "https://example.com/a.pkg.tar.zst" || pkgs[1].SHA256 != "def" {
		t.Fatalf("pkgs = %+v", pkgs)
	}
}

func TestVerifyAndExtract(t *testing.T) {
	pkg := makePackage(t, map[string]string{
		"mingw64/bin/certutil.exe": "binary",
		"mingw64/bin/nss3.dll":     "dll",
		"mingw64/share/doc/readme": "ignore",
	})
	out := t.TempDir()
	want := []string{"mingw64/bin/certutil.exe", "mingw64/bin/nss3.dll"}
	if err := VerifyAndExtract(bytes.NewReader(pkg), want, out); err != nil {
		t.Fatal(err)
	}
	for _, name := range want {
		p := filepath.Join(out, filepath.Base(name))
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing %s", p)
		}
	}
}
