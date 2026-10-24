package nss

import (
	"context"
	"strings"
	"testing"
)

type fakeExec struct {
	calls          [][]string
	stdout, stderr []byte
	err            error
}

func (f *fakeExec) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.stdout, f.stderr, f.err
}

func TestHasPrimaryPasswordNotSet(t *testing.T) {
	f := &fakeExec{}
	c := &Certutil{Path: "certutil", Exec: f}
	got, err := c.HasPrimaryPassword(context.Background(), "C:/profile")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("want false")
	}
}

func TestCheckUsesBuildFlags(t *testing.T) {
	f := &fakeExec{}
	c := &Certutil{Path: "certutil", Exec: f}
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls[0], " ")
	if !strings.Contains(joined, "--build-flags") {
		t.Fatalf("args = %s, want --build-flags", joined)
	}
}

func TestHasPrimaryPasswordSet(t *testing.T) {
	f := &fakeExec{stderr: []byte("Enter Password or Pin for NSS Certificate DB:"), err: context.DeadlineExceeded}
	c := &Certutil{Path: "certutil", Exec: f}
	got, err := c.HasPrimaryPassword(context.Background(), "C:/profile")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("want true")
	}
}

func TestAddUsesDistrustTrust(t *testing.T) {
	f := &fakeExec{}
	c := &Certutil{Path: "certutil", Exec: f}
	if err := c.Add(context.Background(), "C:/profile", "rootvote:abc", []byte("PEM")); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls[0], " ")
	for _, want := range []string{"-A", "-n rootvote:abc", "-t p,p,p", "-i"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args = %s, want %s", joined, want)
		}
	}
}

func TestListEntries(t *testing.T) {
	f := &fakeExec{stdout: []byte(strings.Join([]string{
		"Certificate Nickname                                         Trust Attributes",
		"                                                             SSL,S/MIME,JAR/XPI",
		"rootvote:abc                                                 p,p,p",
		"Some CA                                                      CT,C,C",
	}, string(rune(10))))}
	c := &Certutil{Path: "certutil", Exec: f}
	entries, err := c.ListEntries(context.Background(), "C:/profile")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Nick != "rootvote:abc" || entries[0].Trust != "p,p,p" {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
}
