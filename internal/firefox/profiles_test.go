package firefox

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
	}, string(rune(10)))

	profiles, err := ParseINI(strings.NewReader(ini), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("profiles = %d, want 2", len(profiles))
	}
	if profiles[0].CertDB != filepath.Join(dataDir, "Profiles", "abc.default", "cert9.db") {
		t.Fatalf("profile[0] = %+v", profiles[0])
	}
	if profiles[1].CertDB != filepath.Join(abs, "cert9.db") {
		t.Fatalf("profile[1] = %+v", profiles[1])
	}
}

func TestDiscoverSkipsMissingCert9(t *testing.T) {
	dataDir := t.TempDir()
	writeFile(t, filepath.Join(dataDir, "Profiles", "a.default", "cert8.db"))
	ini := strings.Join([]string{
		"[Profile0]",
		"Name=a",
		"IsRelative=1",
		"Path=Profiles/a.default",
	}, string(rune(10)))
	if err := os.WriteFile(filepath.Join(dataDir, "profiles.ini"), []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	profiles, warnings, err := Discover(dataDir, nil)
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

func TestIsRunning(t *testing.T) {
	dir := t.TempDir()
	if IsRunning(dir) {
		t.Fatal("empty dir should not be running")
	}
	writeFile(t, filepath.Join(dir, "parent.lock"))
	if !IsRunning(dir) {
		t.Fatal("parent.lock should mark running")
	}
}
