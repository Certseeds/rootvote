package nssprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeProfilesINI(t *testing.T, dataDir, body string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "profiles.ini"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseINIRelativeAndAbsolute(t *testing.T) {
	dataDir := t.TempDir()
	writeFile(t, filepath.Join(dataDir, "Profiles", "abc.default", "cert9.db"))
	abs := filepath.Join(t.TempDir(), "custom")
	writeFile(t, filepath.Join(abs, "cert9.db"))

	ini := strings.Join([]string{
		"[General]",
		"Version=2",
		"",
		"[Profile0]",
		"Name=default",
		"IsRelative=1",
		"Path=Profiles/abc.default",
		"",
		"[Profile1]",
		"Name=custom",
		"IsRelative=0",
		"Path=" + abs,
	}, "\n")

	profiles, err := ParseINI(strings.NewReader(ini), dataDir, AppThunderbird)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("profiles = %d, want 2", len(profiles))
	}
	if profiles[0].App != AppThunderbird {
		t.Fatalf("app = %q", profiles[0].App)
	}
	if profiles[0].CertDB != filepath.Join(dataDir, "Profiles", "abc.default", "cert9.db") {
		t.Fatalf("profile[0] = %+v", profiles[0])
	}
	if profiles[1].CertDB != filepath.Join(abs, "cert9.db") {
		t.Fatalf("profile[1] = %+v", profiles[1])
	}
}

func TestDiscoverGeckoSkipsMissingCert9(t *testing.T) {
	dataDir := t.TempDir()
	writeFile(t, filepath.Join(dataDir, "Profiles", "a.default", "cert8.db"))
	writeProfilesINI(t, dataDir, strings.Join([]string{
		"[Profile0]",
		"Name=a",
		"IsRelative=1",
		"Path=Profiles/a.default",
	}, "\n"))

	profiles, warnings, err := DiscoverGecko(dataDir, AppFirefox, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 0 {
		t.Fatalf("profiles = %d, want 0", len(profiles))
	}
	if len(warnings) == 0 {
		t.Fatal("want warning for cert8-only profile")
	}
}

func TestDiscoverGeckoExplicitCert9MustExist(t *testing.T) {
	_, _, err := DiscoverGecko(t.TempDir(), AppFirefox, []string{filepath.Join(t.TempDir(), "missing", "cert9.db")})
	if err == nil {
		t.Fatal("want error for missing explicit cert9.db")
	}
}

func TestDiscoverGeckoExplicitCert9(t *testing.T) {
	db := filepath.Join(t.TempDir(), "custom", "cert9.db")
	writeFile(t, db)
	profiles, _, err := DiscoverGecko(t.TempDir(), AppFirefox, []string{db})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].CertDB != db || profiles[0].App != AppFirefox {
		t.Fatalf("profiles = %+v", profiles)
	}
}

func TestIsRunningGecko(t *testing.T) {
	dir := t.TempDir()
	p := Profile{App: AppFirefox, Dir: dir}
	if IsRunning(p) {
		t.Fatal("empty dir should not be running")
	}
	writeFile(t, filepath.Join(dir, "parent.lock"))
	if !IsRunning(p) {
		t.Fatal("parent.lock should mark running")
	}
}
