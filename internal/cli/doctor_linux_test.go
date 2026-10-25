//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveNSSPathFromPATH(t *testing.T) {
	dir := t.TempDir()
	certutil := filepath.Join(dir, "certutil")
	if err := os.WriteFile(certutil, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	got := resolveNSSPath("")
	if got != certutil {
		t.Fatalf("resolveNSSPath = %q, want %q", got, certutil)
	}
}

func TestResolveNSSPathExplicitWins(t *testing.T) {
	if got := resolveNSSPath("/custom/certutil"); got != "/custom/certutil" {
		t.Fatalf("resolveNSSPath = %q", got)
	}
}
