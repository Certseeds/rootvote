//go:build windows

package platform

import (
	"errors"
	"os"
	"path/filepath"
)

func StatePath() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", os.ErrNotExist
	}
	return filepath.Join(base, "rootvote", "state.json"), nil
}

func FirefoxDataDir() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		return "", os.ErrNotExist
	}
	return filepath.Join(base, "Mozilla", "Firefox"), nil
}

func ExeSuffix() string {
	return ".exe"
}

func ThunderbirdDataDir() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		return "", os.ErrNotExist
	}
	return filepath.Join(base, "Thunderbird"), nil
}

func ChromiumDataDir() (string, error) {
	return "", errors.New("Windows 不使用用户级 NSS")
}

func StatePathForScope(scope Scope) (string, error) {
	return StatePath()
}

func StateType() string { return "windows" }

func SystemScopes() []Scope { return []Scope{ScopeUser, ScopeMachine} }
