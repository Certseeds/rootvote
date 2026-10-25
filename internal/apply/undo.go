package apply

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Certseeds/rootvote/internal/exitcode"
	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nssprofile"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

type UndoOptions struct {
	ManifestDir string
	Scope       platform.Scope
	Targets     []string
	Cert9Paths  []string
	All         bool
	Force       bool
	DryRun      bool
	StatePath   string
}

func RunUndo(ctx context.Context, opts UndoOptions, deps Deps) (Result, error) {
	var res Result
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Out == nil {
		deps.Out = io.Discard
	}

	st, err := state.Load(opts.StatePath)
	if err != nil {
		return res, &Error{Code: exitcode.Error, Err: err}
	}
	if len(st.Applied) == 0 {
		if !opts.Force {
			return res, &Error{Code: exitcode.Error, Err: errors.New("状态文件为空;如确需按清单删除,使用 --force")}
		}
		return forceUndo(ctx, opts, deps, &res)
	}

	var wanted map[string]bool
	if !opts.All {
		m, err := manifest.Verify(opts.ManifestDir)
		if err != nil {
			return res, &Error{Code: exitcode.ManifestInvalid, Err: err}
		}
		wanted = make(map[string]bool, len(m.Entries))
		for _, e := range m.Entries {
			wanted[e.SHA256] = true
		}
	}

	storeCache := make(map[platform.Scope][]platform.Store)
	defer func() {
		for _, stores := range storeCache {
			for _, s := range stores {
				s.Close()
			}
		}
	}()

	var remaining []state.Record
	for _, r := range st.Applied {
		if !opts.All && !wanted[r.SHA256] {
			remaining = append(remaining, r)
			continue
		}
		if opts.DryRun {
			res.Added++
			remaining = append(remaining, r)
			continue
		}
		if r.Type == "windows" || r.Type == "debian" {
			scope := platform.Scope(r.Scope)
			stores, ok := storeCache[scope]
			if !ok {
				stores, err = deps.OpenStores(scope)
				if err != nil {
					remaining = append(remaining, r)
					res.Failed++
					continue
				}
				storeCache[scope] = stores
			}
			sha1bytes, _ := hex.DecodeString(r.SHA1)
			var sum [20]byte
			copy(sum[:], sha1bytes)
			for _, s := range stores {
				if err := s.Unblock(sum); err != nil {
					res.Failed++
					fmt.Fprintln(deps.Out, "撤销失败:", s.Scope(), r.SHA256, err)
					remaining = append(remaining, r)
					continue
				}
				res.Added++
			}
			continue
		}
		if isNSSApp(r.Type) && deps.Certutil != nil {
			var err error
			if r.Previous == "existing" || r.PreviousTrust != "" {
				trust := r.PreviousTrust
				if trust == "" {
					trust = ",,"
				}
				err = deps.Certutil.SetTrust(ctx, r.Profile, r.Nickname, trust)
			} else {
				err = deps.Certutil.Delete(ctx, r.Profile, r.Nickname)
			}
			if err != nil {
				res.Failed++
				fmt.Fprintln(deps.Out, r.Type, "撤销失败:", r.Profile, r.SHA256, err)
				remaining = append(remaining, r)
				continue
			}
			res.Added++
			continue
		}
		remaining = append(remaining, r)
	}
	st.Applied = remaining
	if !opts.DryRun {
		if err := st.Save(opts.StatePath); err != nil {
			if os.IsPermission(err) {
				return res, &Error{Code: exitcode.Permission, Err: err}
			}
			return res, &Error{Code: exitcode.Error, Err: err}
		}
	}
	return res, nil
}

func forceUndo(ctx context.Context, opts UndoOptions, deps Deps, res *Result) (Result, error) {
	m, err := manifest.Verify(opts.ManifestDir)
	if err != nil {
		return *res, &Error{Code: exitcode.ManifestInvalid, Err: err}
	}
	ders, err := manifest.LoadCerts(opts.ManifestDir)
	if err != nil {
		return *res, &Error{Code: exitcode.ManifestInvalid, Err: err}
	}
	if len(opts.Targets) == 0 {
		opts.Targets = platform.DefaultTargetsForScope(opts.Scope)
	}
	opts.Targets = uniqueTargets(opts.Targets)
	opts.Targets = skipUnsupportedTargets(deps.Out, opts.Targets)
	extra, err := nssprofile.GroupCert9Paths(opts.Cert9Paths)
	if err != nil {
		return *res, &Error{Code: exitcode.Usage, Err: err}
	}
	if deps.IsRunning == nil {
		deps.IsRunning = func(nssprofile.Profile) bool { return false }
	}

	for _, t := range opts.Targets {
		switch {
		case t == TargetSystem:
			stores, err := deps.OpenStores(opts.Scope)
			if err != nil {
				if errors.Is(err, platform.ErrPermission) {
					return *res, &Error{Code: exitcode.Permission, Err: err}
				}
				return *res, &Error{Code: exitcode.Error, Err: err}
			}
			for _, e := range m.Entries {
				sum := sha1.Sum(ders[e.SHA256])
				for _, s := range stores {
					ok, err := s.Blocked(sum)
					if err != nil {
						res.Failed++
						fmt.Fprintln(deps.Out, "查询失败:", s.Scope(), e.SHA256, err)
						continue
					}
					if !ok {
						continue
					}
					if opts.DryRun {
						res.Added++
						continue
					}
					if err := s.Unblock(sum); err != nil {
						res.Failed++
						fmt.Fprintln(deps.Out, "强制撤销失败:", s.Scope(), e.SHA256, err)
						continue
					}
					res.Added++
				}
			}
			for _, s := range stores {
				s.Close()
			}

		case isNSSApp(t):
			if deps.Certutil == nil || deps.DiscoverProfiles == nil {
				continue
			}
			app := nssprofile.App(t)
			profiles, warnings, err := deps.DiscoverProfiles(app, extra[app])
			if err != nil {
				return *res, &Error{Code: exitcode.Error, Err: err}
			}
			for _, w := range warnings {
				fmt.Fprintln(deps.Out, "警告:", w)
			}
			for _, p := range profiles {
				if deps.IsRunning(p) {
					return *res, &Error{Code: exitcode.AppRunning, Err: fmt.Errorf("%s 正在运行: %s", p.App, p.Dir)}
				}
				has, err := deps.Certutil.HasPrimaryPassword(ctx, p.Dir)
				if has || err != nil {
					res.SkippedProfiles = append(res.SkippedProfiles, p.ID())
					fmt.Fprintln(deps.Out, "跳过 profile(主密码):", p.ID())
					continue
				}
				for _, e := range m.Entries {
					nick := "rootvote:" + e.SHA256[:16]
					ok, err := deps.Certutil.HasNickname(ctx, p.Dir, nick)
					if err != nil || !ok {
						continue
					}
					if opts.DryRun {
						res.Added++
						continue
					}
					if err := deps.Certutil.Delete(ctx, p.Dir, nick); err != nil {
						res.Failed++
						fmt.Fprintln(deps.Out, "强制撤销失败:", p.ID(), e.SHA256, err)
						continue
					}
					res.Added++
				}
			}
		}
	}
	return *res, nil
}
