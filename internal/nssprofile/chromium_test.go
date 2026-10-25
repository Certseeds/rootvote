package nssprofile

import (
	"path/filepath"
	"testing"
)

func TestDiscoverChromium(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "cert9.db"))
	profiles, warnings, err := DiscoverChromium(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profiles = %+v", profiles)
	}
	if profiles[0].App != AppChromium || profiles[0].Dir != dir {
		t.Fatalf("profile = %+v", profiles[0])
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestDiscoverChromiumMissingCert9(t *testing.T) {
	profiles, warnings, err := DiscoverChromium(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 0 || len(warnings) != 0 {
		t.Fatalf("profiles = %+v warnings = %v", profiles, warnings)
	}
}

func TestDiscoverChromiumExplicitCert9MustExist(t *testing.T) {
	_, _, err := DiscoverChromium("", []string{filepath.Join(t.TempDir(), "missing", "cert9.db")})
	if err == nil {
		t.Fatal("want error for missing explicit cert9.db")
	}
}

func TestDiscoverChromiumExplicitCert9(t *testing.T) {
	db := filepath.Join(t.TempDir(), "custom", "cert9.db")
	writeFile(t, db)
	profiles, _, err := DiscoverChromium("", []string{db})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].CertDB != db {
		t.Fatalf("profiles = %+v", profiles)
	}
}
