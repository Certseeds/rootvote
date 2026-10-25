package nssprofile

import (
	"path/filepath"
	"testing"
)

func TestParseCert9Path(t *testing.T) {
	p, err := ParseCert9Path("thunderbird:" + filepath.Join("data", "Profiles", "abc", "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	if p.App != AppThunderbird {
		t.Fatalf("app = %q", p.App)
	}
	if p.Dir != filepath.Join("data", "Profiles", "abc") {
		t.Fatalf("dir = %q", p.Dir)
	}
	if p.CertDB != filepath.Join("data", "Profiles", "abc", "cert9.db") {
		t.Fatalf("certdb = %q", p.CertDB)
	}
}

func TestParseCert9PathRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "firefox", "safari:/tmp/cert9.db", "firefox:"} {
		if _, err := ParseCert9Path(in); err == nil {
			t.Fatalf("ParseCert9Path(%q) should fail", in)
		}
	}
}

func TestGroupCert9Paths(t *testing.T) {
	got, err := GroupCert9Paths([]string{"firefox:/a/cert9.db", "thunderbird:/b/cert9.db", "firefox:/c/cert9.db"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[AppFirefox]) != 2 || len(got[AppThunderbird]) != 1 {
		t.Fatalf("groups = %#v", got)
	}
}
