package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const Schema = 1

type State struct {
	Schema  int      `json:"schema"`
	Applied []Record `json:"applied"`
}

type Record struct {
	Type           string `json:"type"`
	Scope          string `json:"scope,omitempty"`
	Profile        string `json:"profile,omitempty"`
	SHA256         string `json:"sha256"`
	SHA1           string `json:"sha1,omitempty"`
	Nickname       string `json:"nickname,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	AppliedAt      string `json:"applied_at"`
	Previous       string `json:"previous,omitempty"`
	PreviousTrust  string `json:"previous_trust,omitempty"`
	BackupPath     string `json:"backup_path,omitempty"`
}

func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{Schema: Schema}, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("解析状态文件: %w", err)
	}
	if s.Schema == 0 {
		s.Schema = Schema
	}
	return &s, nil
}

func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *State) Add(r Record) bool {
	for _, x := range s.Applied {
		if x.Type == r.Type && x.Scope == r.Scope && x.Profile == r.Profile && x.SHA256 == r.SHA256 {
			return false
		}
	}
	s.Applied = append(s.Applied, r)
	return true
}

func (s *State) RemoveMatching(fn func(Record) bool) int {
	out := s.Applied[:0]
	removed := 0
	for _, r := range s.Applied {
		if fn(r) {
			removed++
			continue
		}
		out = append(out, r)
	}
	s.Applied = out
	return removed
}
