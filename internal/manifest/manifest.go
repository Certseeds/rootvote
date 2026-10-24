package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const Schema = 1

type Manifest struct {
	Schema        int     `json:"schema"`
	GeneratedAt   string  `json:"generated_at"`
	CCADBSnapshot string  `json:"ccadb_snapshot"`
	Generator     string  `json:"generator"`
	Filter        Filter  `json:"filter"`
	Summary       Summary `json:"summary"`
	Entries       []Entry `json:"entries"`
}

type Filter struct {
	Countries    []string `json:"countries"`
	CountryCodes []string `json:"country_codes"`
	RecordTypes  []string `json:"record_types"`
}

type Summary struct {
	Total         int `json:"total"`
	Roots         int `json:"roots"`
	Intermediates int `json:"intermediates"`
}

type Entry struct {
	SHA256          string `json:"sha256"`
	Subject         string `json:"subject"`
	Issuer          string `json:"issuer"`
	Owner           string `json:"owner"`
	Country         string `json:"country"`
	CertificateName string `json:"certificate_name"`
	RecordType      string `json:"record_type"`
	TLSCapable      bool   `json:"tls_capable"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	File            string `json:"file"`
}

func CertPath(sha string) string {
	return path.Join("certs", sha[:2], sha+".pem")
}

func certFilePath(dir, sha string) string {
	return filepath.Join(dir, filepath.FromSlash(CertPath(sha)))
}

func SnapshotTime(snapshot string) (time.Time, error) {
	s := strings.TrimPrefix(snapshot, "v1.")
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 || len(parts[0]) != 8 || len(parts[1]) > 6 {
		return time.Time{}, fmt.Errorf("无法从版本 %q 解析时间", snapshot)
	}
	clock := parts[1]
	for len(clock) < 6 {
		clock = "0" + clock
	}
	t, err := time.Parse("20060102.150405", parts[0]+"."+clock)
	if err != nil {
		return time.Time{}, fmt.Errorf("无法从版本 %q 解析时间: %w", snapshot, err)
	}
	return t.UTC(), nil
}

func Marshal(m *Manifest) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Write(dir string, m *Manifest, certs map[string][]byte) error {
	tmp := dir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	cleanup := func() { os.RemoveAll(tmp) }
	for sha, pemBytes := range certs {
		p := certFilePath(tmp, sha)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			cleanup()
			return err
		}
		if err := os.WriteFile(p, pemBytes, 0o644); err != nil {
			cleanup()
			return err
		}
	}
	b, err := Marshal(m)
	if err != nil {
		cleanup()
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), b, 0o644); err != nil {
		cleanup()
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		cleanup()
		return err
	}
	return nil
}

func Read(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("解析 manifest.json: %w", err)
	}
	return &m, nil
}

func Verify(dir string) (*Manifest, error) {
	m, err := Read(dir)
	if err != nil {
		return nil, err
	}
	if m.Schema != Schema {
		return nil, fmt.Errorf("不支持的 schema %d", m.Schema)
	}
	seen := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		if len(e.SHA256) != 64 {
			return nil, fmt.Errorf("非法 SHA-256: %q", e.SHA256)
		}
		if seen[e.SHA256] {
			return nil, fmt.Errorf("重复的 SHA-256: %s", e.SHA256)
		}
		seen[e.SHA256] = true
		if e.File != CertPath(e.SHA256) {
			return nil, fmt.Errorf("%s: file 字段与路径规则不一致", e.SHA256)
		}
		b, err := os.ReadFile(certFilePath(dir, e.SHA256))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.SHA256, err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s: PEM 解码失败", e.SHA256)
		}
		sum := sha256.Sum256(block.Bytes)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			return nil, fmt.Errorf("%s: 证书指纹不匹配", e.SHA256)
		}
	}
	if len(m.Entries) != m.Summary.Total {
		return nil, fmt.Errorf("条目数 %d 与 summary.total %d 不一致", len(m.Entries), m.Summary.Total)
	}
	return m, nil
}

func LoadCerts(dir string) (map[string][]byte, error) {
	m, err := Verify(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(certFilePath(dir, e.SHA256))
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s: PEM 解码失败", e.SHA256)
		}
		out[e.SHA256] = block.Bytes
	}
	return out, nil
}

func LoadPEMs(dir string) (map[string][]byte, error) {
	m, err := Verify(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(m.Entries))
	for _, e := range m.Entries {
		b, err := os.ReadFile(certFilePath(dir, e.SHA256))
		if err != nil {
			return nil, err
		}
		out[e.SHA256] = b
	}
	return out, nil
}
