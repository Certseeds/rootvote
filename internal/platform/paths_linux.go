//go:build linux

package platform

import (
	"os"
	"path/filepath"
)

func StatePath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "rootvote", "state.json"), nil
}

func FirefoxDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".mozilla", "firefox"), nil
}

func ExeSuffix() string {
	return ""
}

func ThunderbirdDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".thunderbird"), nil
}

func ChromiumDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".pki", "nssdb"), nil
}

func StatePathForScope(scope Scope) (string, error) {
	return StatePath()
}
