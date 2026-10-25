package nssprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type App string

const (
	AppFirefox     App = "firefox"
	AppThunderbird App = "thunderbird"
	AppChromium    App = "chromium"
)

func (a App) Valid() bool {
	switch a {
	case AppFirefox, AppThunderbird, AppChromium:
		return true
	default:
		return false
	}
}

type Profile struct {
	App    App
	Name   string
	Dir    string
	CertDB string
}

func (p Profile) ID() string { return string(p.App) + ":" + p.Dir }

func newProfile(app App, certDB string) Profile {
	db := filepath.Clean(certDB)
	dir := filepath.Dir(db)
	return Profile{App: app, Name: filepath.Base(dir), Dir: dir, CertDB: db}
}

func ParseCert9Path(value string) (Profile, error) {
	app, rest, ok := strings.Cut(value, ":")
	if !ok || strings.TrimSpace(rest) == "" {
		return Profile{}, fmt.Errorf("--cert9-path 需要 <app>:<cert9.db 路径>,收到 %q", value)
	}
	a := App(app)
	if !a.Valid() {
		return Profile{}, fmt.Errorf("未知的 NSS 应用 %q(可选 firefox/thunderbird/chromium)", app)
	}
	return newProfile(a, rest), nil
}

func GroupCert9Paths(values []string) (map[App][]string, error) {
	out := make(map[App][]string)
	for _, v := range values {
		p, err := ParseCert9Path(v)
		if err != nil {
			return nil, err
		}
		out[p.App] = append(out[p.App], p.CertDB)
	}
	return out, nil
}

func IsRunning(p Profile) bool {
	if p.App == AppChromium {
		return chromiumRunning()
	}
	for _, name := range []string{"parent.lock", "lock", ".parentlock"} {
		if _, err := os.Stat(filepath.Join(p.Dir, name)); err == nil {
			return true
		}
	}
	return false
}
