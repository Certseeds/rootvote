//go:build linux

package nssprofile

import "testing"

func TestIsChromiumProcess(t *testing.T) {
	for _, name := range []string{"chrome", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "msedge"} {
		if !isChromiumProcess(name) {
			t.Fatalf("%q should match", name)
		}
	}
	for _, name := range []string{"firefox", "thunderbird", "bash", "chrome_crashpad_handler", ""} {
		if isChromiumProcess(name) {
			t.Fatalf("%q should not match", name)
		}
	}
}
