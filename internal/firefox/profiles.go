package firefox

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Profile struct {
	Name   string
	Dir    string
	CertDB string
}

func ParseINI(r io.Reader, dataDir string) ([]Profile, error) {
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
			Name:   sec["Name"],
			Dir:    p,
			CertDB: filepath.Join(p, "cert9.db"),
		})
	}
	return out, nil
}

func Discover(dataDir string, extra []string) ([]Profile, []string, error) {
	var profiles []Profile
	var warnings []string

	iniPath := filepath.Join(dataDir, "profiles.ini")
	if f, err := os.Open(iniPath); err == nil {
		parsed, err := ParseINI(f, dataDir)
		f.Close()
		if err != nil {
			return nil, nil, err
		}
		profiles = append(profiles, parsed...)
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}

	for _, dir := range extra {
		profiles = append(profiles, Profile{
			Name:   filepath.Base(dir),
			Dir:    dir,
			CertDB: filepath.Join(dir, "cert9.db"),
		})
	}

	seen := make(map[string]bool)
	var out []Profile
	for _, p := range profiles {
		abs, err := filepath.Abs(p.Dir)
		if err != nil {
			abs = p.Dir
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

func IsRunning(profileDir string) bool {
	for _, name := range []string{"parent.lock", "lock", ".parentlock"} {
		if _, err := os.Stat(filepath.Join(profileDir, name)); err == nil {
			return true
		}
	}
	return false
}
