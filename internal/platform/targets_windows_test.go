//go:build windows

package platform

import "testing"

func TestWindowsTargets(t *testing.T) {
	got := DefaultTargets()
	want := []string{"system", "firefox", "thunderbird"}
	if len(got) != len(want) {
		t.Fatalf("targets = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets = %v", got)
		}
	}
	if err := ValidateTargets(ScopeUser, got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargets(ScopeUser, []string{"chromium"}); err != nil {
		t.Fatal("chromium should be accepted and skipped on Windows")
	}
	if !SkipTarget("chromium") {
		t.Fatal("chromium should be skipped on Windows")
	}
	if SkipTarget("firefox") {
		t.Fatal("firefox should not be skipped on Windows")
	}
}
