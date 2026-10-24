package platform

import (
	"os"
	"path/filepath"
)

func ExePath() (string, error) {
	return os.Executable()
}

func ExeDir() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(p), nil
}

func DefaultManifestDir() (string, error) {
	dir, err := ExeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "blacklist"), nil
}
