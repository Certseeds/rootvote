package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/apply"
	"github.com/Certseeds/rootvote/internal/firefox"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

func (a *app) newUndoCmd() *cobra.Command {
	var manifestPath, scopeStr, statePath, nssPath string
	var firefoxProfiles multiFlag
	var all, force, dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "undo",
		Short: "撤销",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runUndo(manifestPath, scopeStr, firefoxProfiles, statePath, nssPath, all, force, dryRun, yes)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "清单目录")
	cmd.Flags().StringVar(&scopeStr, "scope", "user", "user/machine/all")
	cmd.Flags().Var(&firefoxProfiles, "firefox-profile", "追加 Firefox profile 目录")
	cmd.Flags().StringVar(&statePath, "state", "", "状态文件")
	cmd.Flags().StringVar(&nssPath, "nss-certutil", "", "NSS certutil 路径")
	cmd.Flags().BoolVar(&all, "all", false, "撤销所有 rootvote 记录")
	cmd.Flags().BoolVar(&force, "force", false, "无状态文件时按清单强制删除")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "只显示计划")
	cmd.Flags().BoolVar(&yes, "yes", false, "跳过确认")
	return cmd
}

func (a *app) runUndo(manifestPath, scopeStr string, firefoxProfiles multiFlag, statePath, nssPath string, all, force, dryRun, yes bool) error {
	if !dryRun && !yes {
		if !a.deps.IsTTY() {
			return codeError(ExitUsage, errors.New("非交互环境需要 --yes"))
		}
		if !a.deps.Confirm("继续撤销? [y/N] ") {
			return codeError(ExitError, errors.New("已取消"))
		}
	}

	dir := manifestPath
	if dir == "" {
		dir = defaultManifestDir()
	}
	sp := statePath
	if sp == "" {
		p, err := platform.StatePath()
		if err != nil {
			return codeError(ExitError, err)
		}
		sp = p
	}
	scope, err := platform.ParseScope(scopeStr)
	if err != nil {
		return codeError(ExitUsage, err)
	}

	st, err := state.Load(sp)
	if err != nil {
		return codeError(ExitError, err)
	}
	certutilPath := resolveNSSPath(nssPath)
	ad := apply.Deps{
		OpenStores: platform.Open,
		DiscoverProfiles: func() ([]firefox.Profile, []string, error) {
			dataDir, err := platform.FirefoxDataDir()
			if err != nil {
				return nil, nil, err
			}
			return firefox.Discover(dataDir, firefoxProfiles)
		},
		IsRunning: firefox.IsRunning,
		Certutil:  nss.New(certutilPath),
		State:     st,
		Now:       time.Now,
		Out:       a.stdout,
	}
	opts := apply.UndoOptions{
		ManifestDir: dir,
		Scope:       scope,
		All:         all,
		Force:       force,
		DryRun:      dryRun,
		StatePath:   sp,
	}
	res, err := a.deps.UndoFunc(context.Background(), opts, ad)
	if err != nil {
		var ae *apply.Error
		if errors.As(err, &ae) {
			return codeError(ae.Code, ae.Err)
		}
		return codeError(ExitError, err)
	}
	fmt.Fprintln(a.stdout, "removed:", res.Added, "failed:", res.Failed)
	if res.Failed > 0 {
		return codeError(ExitError, nil)
	}
	return nil
}
