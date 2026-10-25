//go:build linux

package platform

import "fmt"

func DefaultTargets() []string {
	return []string{"firefox", "thunderbird", "chromium"}
}

func DefaultTargetsForScope(scope Scope) []string {
	return DefaultTargets()
}

func ValidateTargets(scope Scope, targets []string) error {
	for _, t := range targets {
		switch t {
		case "system", "firefox", "thunderbird", "chromium":
		default:
			return fmt.Errorf("未知 target %q(可选 system/firefox/thunderbird/chromium)", t)
		}
	}
	return nil
}

func SkipTarget(target string) bool { return false }
