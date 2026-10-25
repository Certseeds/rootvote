//go:build !linux

package nssprofile

func chromiumRunning() bool { return false }
