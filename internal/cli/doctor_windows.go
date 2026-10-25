//go:build windows

package cli

func extraDoctorChecks(check func(bool, string, string), warn func(string, string)) {}
