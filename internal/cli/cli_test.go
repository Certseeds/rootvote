package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	code := RunWithDeps([]string{"version"}, &out, &errb, Deps{Version: "test", Snapshot: "v1.test"})
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}
	if !strings.Contains(out.String(), "rootvote test") {
		t.Fatalf("stdout = %q, want rootvote test", out.String())
	}
	if !strings.Contains(out.String(), "ccadb v1.test") {
		t.Fatalf("stdout = %q, want ccadb v1.test", out.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	code := RunWithDeps([]string{"nope"}, &out, &errb, Deps{})
	if code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errb.String(), "未知命令") {
		t.Fatalf("stderr = %q, want 未知命令", errb.String())
	}
}
