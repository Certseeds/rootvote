//go:build linux

package platform

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type debianPaths struct {
	Conf        string
	Bundle      string
	PackageRoot string
	LocalRoot   string
	StateDir    string
	Index       string
	BackupDir   string
	Lock        string
}

func defaultDebianPaths() debianPaths {
	return debianPaths{
		Conf:        "/etc/ca-certificates.conf",
		Bundle:      "/etc/ssl/certs/ca-certificates.crt",
		PackageRoot: "/usr/share/ca-certificates",
		LocalRoot:   "/usr/local/share/ca-certificates",
		StateDir:    "/var/lib/rootvote",
		Index:       "/var/lib/rootvote/blocked.json",
		BackupDir:   "/var/lib/rootvote/backup",
		Lock:        "/var/lib/rootvote/lock",
	}
}

type debianEntry struct {
	SHA256       string `json:"sha256"`
	SHA1         string `json:"sha1"`
	Kind         string `json:"kind"`
	SourcePath   string `json:"source_path,omitempty"`
	ConfLine     string `json:"conf_line,omitempty"`
	OriginalConf string `json:"original_conf,omitempty"`
	BackupPath   string `json:"backup_path,omitempty"`
	OriginalPath string `json:"original_path,omitempty"`
	BlockedAt    string `json:"blocked_at"`
}

type debianStore struct {
	paths     debianPaths
	run       commandRunner
	updateCmd string
	lock      *os.File
	mu        sync.Mutex
	index     map[string]debianEntry
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func resolveUpdateCommand() string {
	if p, err := exec.LookPath("update-ca-certificates"); err == nil {
		return p
	}
	const fallback = "/usr/sbin/update-ca-certificates"
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	return ""
}

func Open(scope Scope) ([]Store, error) {
	if scope != ScopeMachine {
		return nil, fmt.Errorf("Linux 系统信任库需要 --scope machine(收到 %q)", scope)
	}
	if os.Geteuid() != 0 {
		return nil, ErrPermission
	}
	updateCmd := resolveUpdateCommand()
	if updateCmd == "" {
		return nil, fmt.Errorf("未找到 update-ca-certificates;Debian/Ubuntu 需要 ca-certificates")
	}
	s, err := openDebian(defaultDebianPaths(), runCommand, updateCmd)
	if err != nil {
		return nil, err
	}
	return []Store{s}, nil
}

func openDebian(paths debianPaths, run commandRunner, updateCmd string) (*debianStore, error) {
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(paths.BackupDir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(paths.Lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("另一个 rootvote 实例正在运行: %w", err)
	}
	s := &debianStore{paths: paths, run: run, updateCmd: updateCmd, lock: lock}
	if err := s.loadIndex(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *debianStore) Scope() Scope { return ScopeMachine }

func (s *debianStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	err := s.lock.Close()
	s.lock = nil
	return err
}

func (s *debianStore) loadIndex() error {
	s.index = make(map[string]debianEntry)
	b, err := os.ReadFile(s.paths.Index)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, &s.index); err != nil {
		return fmt.Errorf("解析 %s: %w", s.paths.Index, err)
	}
	return nil
}

func (s *debianStore) saveIndex() error {
	b, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.paths.Index + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.paths.Index)
}

func (s *debianStore) Blocked(sum [20]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.index[hex.EncodeToString(sum[:])]
	return ok, nil
}

func (s *debianStore) Block(der []byte) (BlockResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sha1sum := sha1.Sum(der)
	key := hex.EncodeToString(sha1sum[:])
	if _, ok := s.index[key]; ok {
		return BlockResult{}, nil
	}
	inBundle, err := s.inBundle(sha1sum)
	if err != nil {
		return BlockResult{}, err
	}
	if !inBundle {
		return BlockResult{}, nil
	}
	sha256sum := sha256.Sum256(der)
	src, kind, err := s.findSource(hex.EncodeToString(sha256sum[:]))
	if err != nil {
		return BlockResult{}, err
	}
	if src == "" {
		return BlockResult{}, nil
	}

	confBefore, err := os.ReadFile(s.paths.Conf)
	if err != nil {
		return BlockResult{}, err
	}
	entry := debianEntry{
		SHA256:     hex.EncodeToString(sha256sum[:]),
		SHA1:       key,
		Kind:       kind,
		SourcePath: src,
		BlockedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	var localBefore []byte
	rollback := func() {
		if err := os.WriteFile(s.paths.Conf, confBefore, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "回滚 ca-certificates.conf 失败:", err)
		}
		if entry.BackupPath != "" {
			if localBefore != nil {
				if err := os.WriteFile(entry.OriginalPath, localBefore, 0o644); err != nil {
					fmt.Fprintln(os.Stderr, "回滚本地证书失败:", err)
				}
			}
			os.Remove(entry.BackupPath)
		}
	}

	switch kind {
	case "package":
		rel, err := filepath.Rel(s.paths.PackageRoot, src)
		if err != nil {
			return BlockResult{}, err
		}
		rel = filepath.ToSlash(rel)
		line, _ := findConfLine(confBefore, rel)
		entry.ConfLine = "!" + rel
		entry.OriginalConf = line
		if err := os.WriteFile(s.paths.Conf, setConfLine(confBefore, rel, "!"+rel), 0o644); err != nil {
			return BlockResult{}, err
		}
	case "local":
		localBefore, err = os.ReadFile(src)
		if err != nil {
			return BlockResult{}, err
		}
		backup := filepath.Join(s.paths.BackupDir, entry.SHA256+".crt")
		if err := copyFile(src, backup); err != nil {
			return BlockResult{}, err
		}
		entry.BackupPath = backup
		entry.OriginalPath = src
		if err := os.Remove(src); err != nil {
			rollback()
			return BlockResult{}, err
		}
	default:
		return BlockResult{}, fmt.Errorf("未知的证书来源 %q", kind)
	}

	if err := s.runUpdate(context.Background()); err != nil {
		rollback()
		return BlockResult{}, err
	}
	s.index[key] = entry
	if err := s.saveIndex(); err != nil {
		delete(s.index, key)
		rollback()
		_ = s.runUpdate(context.Background())
		return BlockResult{}, err
	}
	return BlockResult{Changed: true, BackupPath: entry.BackupPath}, nil
}

func (s *debianStore) Unblock(sum [20]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hex.EncodeToString(sum[:])
	entry, ok := s.index[key]
	if !ok {
		return nil
	}
	confBefore, err := os.ReadFile(s.paths.Conf)
	if err != nil {
		return err
	}
	var restore func()
	switch entry.Kind {
	case "package":
		rel := strings.TrimPrefix(entry.ConfLine, "!")
		if err := os.WriteFile(s.paths.Conf, unsetConfLine(confBefore, rel, entry.OriginalConf), 0o644); err != nil {
			return err
		}
		restore = func() { _ = os.WriteFile(s.paths.Conf, confBefore, 0o644) }
	case "local":
		if entry.BackupPath == "" {
			return fmt.Errorf("索引缺少备份路径: %s", key)
		}
		if err := copyFile(entry.BackupPath, entry.OriginalPath); err != nil {
			return err
		}
		restore = func() { _ = os.Remove(entry.OriginalPath) }
	default:
		return fmt.Errorf("未知的证书来源 %q", entry.Kind)
	}

	if err := s.runUpdate(context.Background()); err != nil {
		restore()
		return err
	}
	delete(s.index, key)
	if err := s.saveIndex(); err != nil {
		s.index[key] = entry
		restore()
		return err
	}
	if entry.Kind == "local" {
		_ = os.Remove(entry.BackupPath)
	}
	return nil
}

func (s *debianStore) runUpdate(ctx context.Context) error {
	out, err := s.run(ctx, s.updateCmd, "--fresh")
	if err != nil {
		return fmt.Errorf("update-ca-certificates --fresh: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *debianStore) inBundle(want [20]byte) (bool, error) {
	b, err := os.ReadFile(s.paths.Bundle)
	if err != nil {
		return false, err
	}
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if sha1.Sum(block.Bytes) == want {
			return true, nil
		}
	}
	return false, nil
}

func (s *debianStore) findSource(sha256hex string) (string, string, error) {
	roots := []struct{ dir, kind string }{
		{s.paths.LocalRoot, "local"},
		{s.paths.PackageRoot, "package"},
	}
	for _, root := range roots {
		var found string
		_ = filepath.WalkDir(root.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".crt") {
				return nil
			}
			der, err := readCertPEM(path)
			if err != nil {
				return nil
			}
			sum := sha256.Sum256(der)
			if hex.EncodeToString(sum[:]) == sha256hex {
				found = path
				return fs.SkipAll
			}
			return nil
		})
		if found != "" {
			return found, root.kind, nil
		}
	}
	return "", "", nil
}

func findConfLine(conf []byte, rel string) (string, bool) {
	for _, line := range strings.Split(string(conf), "\n") {
		l := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.TrimPrefix(l, "!") == rel {
			return strings.TrimPrefix(l, "!"), true
		}
	}
	return "", false
}

func setConfLine(conf []byte, rel, newLine string) []byte {
	lines := strings.Split(string(conf), "\n")
	found := false
	for i, line := range lines {
		l := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.TrimPrefix(l, "!") == rel {
			lines[i] = newLine
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, newLine)
	}
	return []byte(strings.Join(lines, "\n"))
}

func unsetConfLine(conf []byte, rel, original string) []byte {
	lines := strings.Split(string(conf), "\n")
	for i, line := range lines {
		l := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if l != "!"+rel {
			continue
		}
		if original == "" {
			lines = append(lines[:i], lines[i+1:]...)
		} else {
			lines[i] = original
		}
		break
	}
	return []byte(strings.Join(lines, "\n"))
}

func readCertPEM(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: 不是 PEM 证书", path)
	}
	return block.Bytes, nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}
