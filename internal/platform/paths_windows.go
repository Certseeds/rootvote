//go:build windows

package platform

import (
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
