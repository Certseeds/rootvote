//go:build linux

package platform

import "fmt"

func DefaultTargets() []string {
	return []string{"firefox", "thunderbird", "chromium"}
}

func DefaultTargetsForScope(scope Scope) []string {
	switch scope {
	case ScopeUser:
		return []string{"firefox", "thunderbird", "chromium"}
	case ScopeMachine:
		return []string{"system"}
	default:
		return nil
	}
}

func ValidateTargets(scope Scope, targets []string) error {
	switch scope {
	case ScopeUser:
		for _, t := range targets {
			switch t {
			case "firefox", "thunderbird", "chromium":
			case "system":
				return fmt.Errorf("--scope user 不能包含 system;系统信任库需要 --scope machine 与 root")
			default:
				return fmt.Errorf("未知 target %q(可选 firefox/thunderbird/chromium)", t)
			}
		}
	case ScopeMachine:
		for _, t := range targets {
			if t != "system" {
				return fmt.Errorf("--scope machine 只能包含 system;NSS profile 请用 --scope user")
			}
		}
	case ScopeAll:
		return fmt.Errorf("Linux 不支持 --scope all;请分别以 user 和 machine 运行")
	default:
		return fmt.Errorf("无效的 scope %q(可选 user/machine)", scope)
	}
	return nil
}

func SkipTarget(target string) bool { return false }
