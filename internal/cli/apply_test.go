package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Certseeds/rootvote/internal/apply"
)

func TestApplyNonTTYRequiresYes(t *testing.T) {
	deps := Deps{
		IsTTY:   func() bool { return false },
		Confirm: func(string) bool { return false },
		ApplyFunc: func(context.Context, apply.Options, apply.Deps) (apply.Result, error) {
			t.Fatal("ApplyFunc should not be called")
			return apply.Result{}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{"apply", "--browsers", "system"}, &stdout, &stderr, deps)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
}

func TestApplyDryRun(t *testing.T) {
	deps := Deps{
		IsTTY:   func() bool { return true },
		Confirm: func(string) bool { return true },
		ApplyFunc: func(ctx context.Context, opts apply.Options, ad apply.Deps) (apply.Result, error) {
			if !opts.DryRun {
				t.Fatal("want dry run")
			}
			return apply.Result{Added: 2, Skipped: 1}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{
		"apply", "--dry-run", "--yes", "--scope", "machine", "--browsers", "system",
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--manifest", filepath.Join(t.TempDir(), "blacklist"),
	}, &stdout, &stderr, deps)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "added") {
		t.Fatalf("stdout = %s", stdout.String())
	}
}

func TestApplyMapsPermissionError(t *testing.T) {
	deps := Deps{
		IsTTY:   func() bool { return true },
		Confirm: func(string) bool { return true },
		ApplyFunc: func(context.Context, apply.Options, apply.Deps) (apply.Result, error) {
			return apply.Result{}, &apply.Error{Code: ExitPermission, Err: context.DeadlineExceeded}
		},
	}
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{
		"apply", "--dry-run", "--yes", "--scope", "machine", "--browsers", "system",
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--manifest", filepath.Join(t.TempDir(), "blacklist"),
	}, &stdout, &stderr, deps)
	if code != ExitPermission {
		t.Fatalf("exit = %d, want %d", code, ExitPermission)
	}
}

func TestApplyTargetsFlag(t *testing.T) {
	var got apply.Options
	deps := Deps{
		IsTTY:   func() bool { return true },
		Confirm: func(string) bool { return true },
		ApplyFunc: func(_ context.Context, opts apply.Options, _ apply.Deps) (apply.Result, error) {
			got = opts
			return apply.Result{}, nil
		},
	}
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{
		"apply", "--dry-run", "--yes", "--scope", "machine", "--targets", "system",
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--manifest", filepath.Join(t.TempDir(), "blacklist"),
	}, &stdout, &stderr, deps)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if len(got.Targets) != 1 || got.Targets[0] != "system" {
		t.Fatalf("targets = %v", got.Targets)
	}
}

func TestApplyCert9PathIsNotCommaSplit(t *testing.T) {
	var got apply.Options
	deps := Deps{
		IsTTY:   func() bool { return true },
		Confirm: func(string) bool { return true },
		ApplyFunc: func(_ context.Context, opts apply.Options, _ apply.Deps) (apply.Result, error) {
			got = opts
			return apply.Result{}, nil
		},
	}
	certutil := filepath.Join(t.TempDir(), "certutil")
	if err := os.WriteFile(certutil, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	value := "firefox:" + filepath.Join(t.TempDir(), "a,b", "cert9.db")
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{
		"apply", "--dry-run", "--yes", "--targets", "firefox",
		"--cert9-path", value, "--nss-certutil", certutil,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--manifest", filepath.Join(t.TempDir(), "blacklist"),
	}, &stdout, &stderr, deps)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if len(got.Cert9Paths) != 1 || got.Cert9Paths[0] != value {
		t.Fatalf("cert9 paths = %v", got.Cert9Paths)
	}
}

func TestApplyTargetsAndBrowsersConflict(t *testing.T) {
	deps := Deps{
		IsTTY:   func() bool { return true },
		Confirm: func(string) bool { return true },
	}
	var stdout, stderr bytes.Buffer
	code := RunWithDeps([]string{
		"apply", "--dry-run", "--yes", "--scope", "machine",
		"--targets", "system", "--browsers", "system",
		"--state", filepath.Join(t.TempDir(), "state.json"),
	}, &stdout, &stderr, deps)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
}
