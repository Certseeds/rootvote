package apply

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Certseeds/rootvote/internal/exitcode"
	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/nssprofile"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

const (
	TargetSystem      = "system"
	TargetFirefox     = "firefox"
	TargetThunderbird = "thunderbird"
	TargetChromium    = "chromium"
)

type Options struct {
	ManifestDir string
	Scope       platform.Scope
	Targets     []string
	Cert9Paths  []string
	StatePath   string
	DryRun      bool
	AllowEmpty  bool
}

type Deps struct {
	OpenStores       func(platform.Scope) ([]platform.Store, error)
	DiscoverProfiles func(nssprofile.App, []string) ([]nssprofile.Profile, []string, error)
	IsRunning        func(nssprofile.Profile) bool
	Certutil         *nss.Certutil
	State            *state.State
	Now              func() time.Time
	Out              io.Writer
}

type TargetResult struct {
	Name    string
	Added   int
	Skipped int
	Failed  int
}

type Result struct {
	Added, Skipped, Failed int
	Targets                []TargetResult
	SkippedProfiles        []string
}

func (r *Result) add(tr TargetResult) {
	r.Targets = append(r.Targets, tr)
	r.Added += tr.Added
	r.Skipped += tr.Skipped
	r.Failed += tr.Failed
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

func isNSSApp(target string) bool { return nssprofile.App(target).Valid() }

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
	if deps.DiscoverProfiles == nil {
		deps.DiscoverProfiles = func(nssprofile.App, []string) ([]nssprofile.Profile, []string, error) {
			return nil, nil, nil
		}
	}
	if deps.IsRunning == nil {
		deps.IsRunning = func(nssprofile.Profile) bool { return false }
	}

	if len(opts.Targets) == 0 {
		opts.Targets = platform.DefaultTargetsForScope(opts.Scope)
	}
	opts.Targets = uniqueTargets(opts.Targets)
	if err := platform.ValidateTargets(opts.Scope, opts.Targets); err != nil {
		return res, &Error{Code: exitcode.Usage, Err: err}
	}
	opts.Targets = skipUnsupportedTargets(deps.Out, opts.Targets)
	if len(opts.Targets) == 0 {
		return res, &Error{Code: exitcode.Usage, Err: errors.New("没有可用的 target")}
	}
	extra, err := nssprofile.GroupCert9Paths(opts.Cert9Paths)
	if err != nil {
		return res, &Error{Code: exitcode.Usage, Err: err}
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

	hasNSS := false
	for _, t := range opts.Targets {
		if isNSSApp(t) {
			hasNSS = true
			break
		}
	}
	if hasNSS && deps.Certutil == nil {
		return res, &Error{Code: exitcode.NSSMissing, Err: errors.New("未找到 NSS certutil")}
	}

	profiles := make(map[string][]nssprofile.Profile)
	skipProfile := make(map[string]bool)
	if hasNSS {
		for _, t := range opts.Targets {
			app := nssprofile.App(t)
			if !app.Valid() {
				continue
			}
			ps, warnings, err := deps.DiscoverProfiles(app, extra[app])
			if err != nil {
				return res, &Error{Code: exitcode.Error, Err: err}
			}
			for _, w := range warnings {
				fmt.Fprintln(deps.Out, "警告:", w)
			}
			for _, p := range ps {
				if deps.IsRunning(p) {
					return res, &Error{Code: exitcode.AppRunning, Err: fmt.Errorf("%s 正在运行: %s", p.App, p.Dir)}
				}
			}
			for _, p := range ps {
				has, err := deps.Certutil.HasPrimaryPassword(ctx, p.Dir)
				if has || err != nil {
					skipProfile[p.ID()] = true
					res.SkippedProfiles = append(res.SkippedProfiles, p.ID())
					fmt.Fprintln(deps.Out, "跳过 profile(主密码):", p.ID())
				}
			}
			profiles[t] = ps
		}
	}

	var stores []platform.Store
	defer func() {
		for _, s := range stores {
			s.Close()
		}
	}()
	for _, t := range opts.Targets {
		if t != TargetSystem {
			continue
		}
		stores, err = deps.OpenStores(opts.Scope)
		if err != nil {
			if errors.Is(err, platform.ErrPermission) {
				return res, &Error{Code: exitcode.Permission, Err: err}
			}
			return res, &Error{Code: exitcode.Error, Err: err}
		}
		break
	}

	for _, t := range opts.Targets {
		switch {
		case t == TargetSystem:
			tr := TargetResult{Name: "system:" + string(opts.Scope)}
			for _, e := range m.Entries {
				der := ders[e.SHA256]
				sum := sha1.Sum(der)
				allPresent := true
				for _, s := range stores {
					ok, err := s.Contains(sum)
					if err != nil {
						tr.Failed++
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
						tr.Failed++
						fmt.Fprintln(deps.Out, "添加失败:", s.Scope(), e.SHA256, err)
						continue
					}
					deps.State.Add(state.Record{
						Type: "windows", Scope: string(s.Scope()), SHA256: e.SHA256,
						SHA1: hex.EncodeToString(sum[:]), ManifestSHA256: manifestHash,
						AppliedAt: deps.Now().UTC().Format(time.RFC3339),
					})
				}
				if allPresent {
					tr.Skipped++
				} else {
					tr.Added++
				}
			}
			res.add(tr)

		case isNSSApp(t):
			for _, p := range profiles[t] {
				tr := TargetResult{Name: p.ID()}
				if skipProfile[p.ID()] {
					res.add(tr)
					continue
				}
				for _, e := range m.Entries {
					nick := "rootvote:" + e.SHA256[:16]
					exists, _ := deps.Certutil.HasNickname(ctx, p.Dir, nick)
					if exists {
						tr.Skipped++
						continue
					}
					if opts.DryRun {
						tr.Added++
						continue
					}
					if err := deps.Certutil.Add(ctx, p.Dir, nick, pems[e.SHA256]); err != nil {
						existingNick, trust, found, findErr := findExistingProfile(ctx, deps.Certutil, p.Dir, e.SHA256)
						if (findErr != nil || !found) && isReusedIssuerSerial(err) {
							existingNick, trust, found, findErr = findExistingProfileByIssuerSerial(ctx, deps.Certutil, p.Dir, ders[e.SHA256])
						}
						if findErr == nil && found {
							if isProhibited(trust) {
								tr.Skipped++
								continue
							}
							if setErr := deps.Certutil.SetTrust(ctx, p.Dir, existingNick, "p,p,p"); setErr == nil {
								tr.Added++
								deps.State.Add(state.Record{
									Type: string(p.App), Profile: p.Dir, SHA256: e.SHA256, Nickname: existingNick,
									Previous: "existing", PreviousTrust: trust, ManifestSHA256: manifestHash,
									AppliedAt: deps.Now().UTC().Format(time.RFC3339),
								})
								continue
							}
						}
						tr.Failed++
						fmt.Fprintln(deps.Out, "NSS 添加失败:", p.ID(), e.SHA256, err)
						continue
					}
					tr.Added++
					deps.State.Add(state.Record{
						Type: string(p.App), Profile: p.Dir, SHA256: e.SHA256, Nickname: nick,
						ManifestSHA256: manifestHash, AppliedAt: deps.Now().UTC().Format(time.RFC3339),
					})
				}
				res.add(tr)
			}

		default:
			return res, &Error{Code: exitcode.Usage, Err: fmt.Errorf("未知 target %q", t)}
		}
	}

	if !opts.DryRun {
		if err := deps.State.Save(opts.StatePath); err != nil {
			if os.IsPermission(err) {
				return res, &Error{Code: exitcode.Permission, Err: err}
			}
			return res, &Error{Code: exitcode.Error, Err: err}
		}
	}
	return res, nil
}

func uniqueTargets(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func skipUnsupportedTargets(out io.Writer, targets []string) []string {
	kept := make([]string, 0, len(targets))
	for _, t := range targets {
		if platform.SkipTarget(t) {
			fmt.Fprintln(out, "跳过 target:", t, "(该平台使用 system)")
			continue
		}
		kept = append(kept, t)
	}
	return kept
}

func findExistingProfile(ctx context.Context, c *nss.Certutil, profileDir, sha string) (string, string, bool, error) {
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

func isReusedIssuerSerial(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SEC_ERROR_REUSED_ISSUER_AND_SERIAL")
}

func isProhibited(trust string) bool {
	parts := strings.Split(trust, ",")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if strings.TrimSpace(p) != "p" {
			return false
		}
	}
	return true
}

func findExistingProfileByIssuerSerial(ctx context.Context, c *nss.Certutil, profileDir string, der []byte) (string, string, bool, error) {
	target, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", false, err
	}
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
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if cert.SerialNumber.Cmp(target.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, target.RawIssuer) {
			return entry.Nick, entry.Trust, true, nil
		}
	}
	return "", "", false, nil
}

func fileHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
