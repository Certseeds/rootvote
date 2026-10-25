package nssprofile

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ParseINI(r io.Reader, dataDir string, app App) ([]Profile, error) {
	type section map[string]string
	var order []string
	sections := make(map[string]section)

	scanner := bufio.NewScanner(r)
	current := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if _, ok := sections[current]; !ok {
				sections[current] = make(section)
				order = append(order, current)
			}
			continue
		}
		if current == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		sections[current][strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var out []Profile
	for _, name := range order {
		if !strings.HasPrefix(name, "Profile") {
			continue
		}
		sec := sections[name]
		p := strings.TrimSpace(sec["Path"])
		if p == "" {
			continue
		}
		if sec["IsRelative"] == "1" {
			p = filepath.Join(dataDir, filepath.FromSlash(p))
		}
		out = append(out, Profile{
			App:    app,
			Name:   sec["Name"],
			Dir:    p,
			CertDB: filepath.Join(p, "cert9.db"),
		})
	}
	return out, nil
}

func DiscoverGecko(dataDir string, app App, extra []string) ([]Profile, []string, error) {
	var profiles []Profile
	iniPath := filepath.Join(dataDir, "profiles.ini")
	if f, err := os.Open(iniPath); err == nil {
		parsed, err := ParseINI(f, dataDir, app)
		f.Close()
		if err != nil {
			return nil, nil, err
		}
		profiles = append(profiles, parsed...)
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}

	var explicit []Profile
	for _, db := range extra {
		explicit = append(explicit, newProfile(app, db))
	}
	return mergeExisting(profiles, explicit)
}

func mergeExisting(discovered, explicit []Profile) ([]Profile, []string, error) {
	for _, p := range explicit {
		if _, err := os.Stat(p.CertDB); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p.CertDB, err)
		}
	}
	seen := make(map[string]bool)
	var out []Profile
	var warnings []string
	for _, p := range append(discovered, explicit...) {
		abs, err := filepath.Abs(p.CertDB)
		if err != nil {
			abs = p.CertDB
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		if _, err := os.Stat(p.CertDB); err != nil {
			if _, err8 := os.Stat(filepath.Join(p.Dir, "cert8.db")); err8 == nil {
				warnings = append(warnings, fmt.Sprintf("%s: 只有旧版 cert8.db,已跳过", p.Dir))
			}
			continue
		}
		out = append(out, p)
	}
	return out, warnings, nil
}
