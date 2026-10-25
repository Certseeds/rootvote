//go:build linux

package nssprofile

import (
	"os"
	"path/filepath"
	"strings"
)

func chromiumRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", name, "comm"))
		if err != nil {
			continue
		}
		if isChromiumProcess(strings.TrimSpace(string(b))) {
			return true
		}
	}
	return false
}

func isChromiumProcess(name string) bool {
	switch name {
	case "chrome", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "msedge":
		return true
	default:
		return false
	}
}
