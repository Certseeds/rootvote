package nssfetch

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

type Package struct {
	URL    string
	SHA256 string
}

func ParseLock(r io.Reader) ([]Package, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var pkgs []Package
	var cur *Package
	for _, raw := range strings.Split(string(b), string(rune(10))) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[package]]" {
			pkgs = append(pkgs, Package{})
			cur = &pkgs[len(pkgs)-1]
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, string(rune(34)))
		switch strings.TrimSpace(key) {
		case "url":
			cur.URL = value
		case "sha256":
			cur.SHA256 = value
		}
	}
	return pkgs, nil
}

func DownloadAndExtract(ctx context.Context, pkg Package, outDir string, want []string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pkg.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "rootvote/0.1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败 %s: %s", pkg.URL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != strings.ToLower(pkg.SHA256) {
		return fmt.Errorf("校验和失败: %s", pkg.URL)
	}
	return VerifyAndExtract(bytes.NewReader(b), want, outDir)
}

func VerifyAndExtract(r io.Reader, want []string, outDir string) error {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	wantSet := make(map[string]bool, len(want))
	for _, w := range want {
		wantSet[w] = true
	}
	found := make(map[string]bool, len(want))

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !wantSet[hdr.Name] {
			continue
		}
		dst := filepath.Join(outDir, filepath.Base(hdr.Name))
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		f.Close()
		found[hdr.Name] = true
	}
	for name := range wantSet {
		if !found[name] {
			return fmt.Errorf("包中缺少文件: %s", name)
		}
	}
	return nil
}
