package cli

import (
	"bytes"
	"context"
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
		"apply", "--dry-run", "--yes", "--browsers", "system",
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
		"apply", "--dry-run", "--yes", "--browsers", "system",
		"--manifest", filepath.Join(t.TempDir(), "blacklist"),
	}, &stdout, &stderr, deps)
	if code != ExitPermission {
		t.Fatalf("exit = %d, want %d", code, ExitPermission)
	}
}
