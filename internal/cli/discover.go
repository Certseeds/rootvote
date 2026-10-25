package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Certseeds/rootvote/internal/nssprofile"
	"github.com/Certseeds/rootvote/internal/platform"
)

type rawMultiFlag []string

func (m *rawMultiFlag) String() string { return strings.Join(*m, ",") }

func (m *rawMultiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func (m *rawMultiFlag) Type() string { return "strings" }

func discoverApp(app nssprofile.App, extra []string) ([]nssprofile.Profile, []string, error) {
	if app == nssprofile.AppChromium {
		dir, err := platform.ChromiumDataDir()
		if err != nil {
			return nil, nil, err
		}
		return nssprofile.DiscoverChromium(dir, extra)
	}
	var (
		dir string
		err error
	)
	switch app {
	case nssprofile.AppFirefox:
		dir, err = platform.FirefoxDataDir()
	case nssprofile.AppThunderbird:
		dir, err = platform.ThunderbirdDataDir()
	default:
		return nil, nil, fmt.Errorf("未知的 NSS 应用 %q", app)
	}
	if err != nil {
		return nil, nil, err
	}
	return nssprofile.DiscoverGecko(dir, app, extra)
}

func discoverDefaults(extra map[nssprofile.App][]string) ([]nssprofile.Profile, []string, error) {
	var out []nssprofile.Profile
	var warnings []string
	seen := make(map[string]bool)
	for _, target := range platform.DefaultTargets() {
		app := nssprofile.App(target)
		if !app.Valid() {
			continue
		}
		ps, w, err := discoverApp(app, extra[app])
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, w...)
		for _, p := range ps {
			if seen[p.ID()] {
				continue
			}
			seen[p.ID()] = true
			out = append(out, p)
		}
	}
	return out, warnings, nil
}

func resolveTargets(targetsStr, browsersStr string, scope platform.Scope) ([]string, error) {
	if targetsStr != "" && browsersStr != "" {
		return nil, fmt.Errorf("--targets 与 --browsers 不能同时使用")
	}
	if targetsStr == "" {
		targetsStr = browsersStr
	}
	if targetsStr == "" {
		return platform.DefaultTargetsForScope(scope), nil
	}
	return splitList(targetsStr), nil
}

func hasNSSApp(targets []string) bool {
	for _, t := range targets {
		if platform.SkipTarget(t) {
			continue
		}
		if nssprofile.App(t).Valid() {
			return true
		}
	}
	return false
}

func cert9PathsFromFlags(cert9, firefoxProfiles rawMultiFlag) []string {
	out := append([]string(nil), cert9...)
	for _, dir := range firefoxProfiles {
		out = append(out, "firefox:"+filepath.Join(dir, "cert9.db"))
	}
	return out
}
