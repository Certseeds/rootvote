package apply

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Certseeds/rootvote/internal/exitcode"
	"github.com/Certseeds/rootvote/internal/firefox"
	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

type Options struct {
	ManifestDir     string
	Scope           platform.Scope
	Browsers        []string
	FirefoxProfiles []string
	StatePath       string
	DryRun          bool
	AllowEmpty      bool
}

type Deps struct {
	OpenStores       func(platform.Scope) ([]platform.Store, error)
	DiscoverProfiles func() ([]firefox.Profile, []string, error)
	IsRunning        func(string) bool
	Certutil         *nss.Certutil
	State            *state.State
	Now              func() time.Time
	Out              io.Writer
}

type Result struct {
	Added, Skipped, Failed int
	SkippedProfiles        []string
}

type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprint("exit code ", e.Code)
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func Run(ctx context.Context, opts Options, deps Deps) (Result, error) {
	var res Result
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Out == nil {
		deps.Out = io.Discard
	}
	if deps.State == nil {
		deps.State = &state.State{Schema: state.Schema}
	}

	m, err := manifest.Verify(opts.ManifestDir)
	if err != nil {
		return res, &Error{Code: exitcode.ManifestInvalid, Err: err}
	}
	if m.Summary.Total == 0 && !opts.AllowEmpty {
		return res, &Error{Code: exitcode.ManifestInvalid, Err: errors.New("清单为空;使用 --allow-empty 才允许应用")}
	}
	ders, err := manifest.LoadCerts(opts.ManifestDir)
	if err != nil {
		return res, &Error{Code: exitcode.ManifestInvalid, Err: err}
	}
	pems, err := manifest.LoadPEMs(opts.ManifestDir)
	if err != nil {
		return res, &Error{Code: exitcode.ManifestInvalid, Err: err}
	}
	manifestHash, _ := fileHash(filepath.Join(opts.ManifestDir, "manifest.json"))

	browsers := parseBrowsers(opts.Browsers)
	var profiles []firefox.Profile
	skipProfile := make(map[string]bool)
	if browsers.firefox {
		if deps.Certutil == nil {
			return res, &Error{Code: exitcode.NSSMissing, Err: errors.New("未找到 NSS certutil")}
		}
		var warnings []string
		profiles, warnings, err = deps.DiscoverProfiles()
		if err != nil {
			return res, &Error{Code: exitcode.Error, Err: err}
		}
		for _, w := range warnings {
			fmt.Fprintln(deps.Out, "警告:", w)
		}
		for _, p := range profiles {
			if deps.IsRunning(p.Dir) {
				return res, &Error{Code: exitcode.FirefoxRunning, Err: fmt.Errorf("Firefox 正在运行: %s", p.Dir)}
			}
		}
		for _, p := range profiles {
			has, err := deps.Certutil.HasPrimaryPassword(ctx, p.Dir)
			if has || err != nil {
				skipProfile[p.Dir] = true
				res.SkippedProfiles = append(res.SkippedProfiles, p.Dir)
				fmt.Fprintln(deps.Out, "跳过 Firefox profile(主密码):", p.Dir)
			}
		}
	}

	if browsers.system {
		stores, err := deps.OpenStores(opts.Scope)
		if err != nil {
			if errors.Is(err, platform.ErrPermission) {
				return res, &Error{Code: exitcode.Permission, Err: err}
			}
			return res, &Error{Code: exitcode.Error, Err: err}
		}
		defer func() {
			for _, s := range stores {
				s.Close()
			}
		}()
		for _, e := range m.Entries {
			der := ders[e.SHA256]
			sha1sum := sha1.Sum(der)
			allPresent := true
			for _, s := range stores {
				ok, err := s.Contains(sha1sum)
				if err != nil {
					res.Failed++
					fmt.Fprintln(deps.Out, "查询失败:", s.Scope(), e.SHA256, err)
					allPresent = false
					continue
				}
				if ok {
					continue
				}
				allPresent = false
				if opts.DryRun {
					continue
				}
				if err := s.Add(der); err != nil {
					res.Failed++
					fmt.Fprintln(deps.Out, "添加失败:", s.Scope(), e.SHA256, err)
					continue
				}
				deps.State.Add(state.Record{
					Type: "windows", Scope: string(s.Scope()), SHA256: e.SHA256,
					SHA1: hex.EncodeToString(sha1sum[:]), ManifestSHA256: manifestHash,
					AppliedAt: deps.Now().UTC().Format(time.RFC3339),
				})
			}
			if allPresent {
				res.Skipped++
			} else {
				res.Added++
			}
		}
	}

	if browsers.firefox {
		for _, p := range profiles {
			if skipProfile[p.Dir] {
				continue
			}
			for _, e := range m.Entries {
				nick := "rootvote:" + e.SHA256[:16]
				exists, _ := deps.Certutil.HasNickname(ctx, p.Dir, nick)
				if exists {
					res.Skipped++
					continue
				}
				if opts.DryRun {
					res.Added++
					continue
				}
				if err := deps.Certutil.Add(ctx, p.Dir, nick, pems[e.SHA256]); err != nil {
					existingNick, trust, found, findErr := findExistingFirefox(ctx, deps.Certutil, p.Dir, e.SHA256)
					if findErr == nil && found {
						if setErr := deps.Certutil.SetTrust(ctx, p.Dir, existingNick, "p,p,p"); setErr == nil {
							res.Added++
							deps.State.Add(state.Record{
								Type: "firefox", Profile: p.Dir, SHA256: e.SHA256, Nickname: existingNick,
								PreviousTrust: trust, ManifestSHA256: manifestHash,
								AppliedAt: deps.Now().UTC().Format(time.RFC3339),
							})
							continue
						}
					}
					res.Failed++
					fmt.Fprintln(deps.Out, "Firefox 添加失败:", p.Dir, e.SHA256, err)
					continue
				}
				res.Added++
				deps.State.Add(state.Record{
					Type: "firefox", Profile: p.Dir, SHA256: e.SHA256, Nickname: nick,
					ManifestSHA256: manifestHash, AppliedAt: deps.Now().UTC().Format(time.RFC3339),
				})
			}
		}
	}

	if !opts.DryRun {
		if err := deps.State.Save(opts.StatePath); err != nil {
			return res, &Error{Code: exitcode.Error, Err: err}
		}
	}
	return res, nil
}

func findExistingFirefox(ctx context.Context, c *nss.Certutil, profileDir, sha string) (string, string, bool, error) {
	entries, err := c.ListEntries(ctx, profileDir)
	if err != nil {
		return "", "", false, err
	}
	for _, entry := range entries {
		pemBytes, err := c.Export(ctx, profileDir, entry.Nick)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			continue
		}
		sum := sha256.Sum256(block.Bytes)
		if hex.EncodeToString(sum[:]) == sha {
			return entry.Nick, entry.Trust, true, nil
		}
	}
	return "", "", false, nil
}

type browserSet struct {
	system, firefox bool
}

func parseBrowsers(values []string) browserSet {
	set := browserSet{}
	for _, v := range values {
		switch v {
		case "system":
			set.system = true
		case "firefox":
			set.firefox = true
		}
	}
	return set
}

func fileHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
