//go:build linux

package platform

import "testing"

func TestLinuxTargets(t *testing.T) {
	got := DefaultTargets()
	want := []string{"firefox", "thunderbird", "chromium"}
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
		t.Fatal(err)
	}
	if err := ValidateTargets(ScopeUser, []string{"chromium"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargets(ScopeUser, []string{"nope"}); err == nil {
		t.Fatal("unknown target should be rejected")
	}
}

func TestLinuxScopeRules(t *testing.T) {
	if err := ValidateTargets(ScopeUser, []string{"firefox", "thunderbird", "chromium"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargets(ScopeUser, []string{"system"}); err == nil {
		t.Fatal("user scope must reject system")
	}
	if err := ValidateTargets(ScopeMachine, []string{"system"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTargets(ScopeMachine, []string{"firefox"}); err == nil {
		t.Fatal("machine scope must reject NSS targets")
	}
	if err := ValidateTargets(ScopeAll, nil); err == nil {
		t.Fatal("scope all must be rejected on Linux")
	}
}
