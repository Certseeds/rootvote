//go:build linux

package platform

import "testing"

func TestLinuxTargets(t *testing.T) {
	got := DefaultTargets()
	want := []string{"firefox", "thunderbird"}
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
	if err := ValidateTargets(ScopeUser, []string{"system", "firefox"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargets(ScopeUser, []string{"nope"}); err == nil {
		t.Fatal("unknown target should be rejected")
	}
}
