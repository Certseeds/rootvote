package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/apply"
	"github.com/Certseeds/rootvote/internal/firefox"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

func (a *app) newApplyCmd() *cobra.Command {
	var manifestPath, scopeStr, browsersStr, statePath, nssPath string
	var firefoxProfiles multiFlag
	var dryRun, yes, allowEmpty bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "应用清单",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runApply(manifestPath, scopeStr, browsersStr, firefoxProfiles, statePath, nssPath, dryRun, yes, allowEmpty)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "清单目录")
	cmd.Flags().StringVar(&scopeStr, "scope", "user", "user/machine/all")
	cmd.Flags().StringVar(&browsersStr, "browsers", "system,firefox", "system,firefox")
	cmd.Flags().Var(&firefoxProfiles, "firefox-profile", "追加 Firefox profile 目录")
	cmd.Flags().StringVar(&statePath, "state", "", "状态文件")
	cmd.Flags().StringVar(&nssPath, "nss-certutil", "", "NSS certutil 路径")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "只显示计划")
	cmd.Flags().BoolVar(&yes, "yes", false, "跳过确认")
	cmd.Flags().BoolVar(&allowEmpty, "allow-empty", false, "允许空清单")
	return cmd
}

func (a *app) runApply(manifestPath, scopeStr, browsersStr string, firefoxProfiles multiFlag, statePath, nssPath string, dryRun, yes, allowEmpty bool) error {
	if !dryRun && !yes {
		if !a.deps.IsTTY() {
			return codeError(ExitUsage, errors.New("非交互环境需要 --yes"))
		}
		if !a.deps.Confirm("继续应用清单? [y/N] ") {
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
	browsers := splitList(browsersStr)
	options := apply.Options{
		ManifestDir:     dir,
		Scope:           scope,
		Browsers:        browsers,
		FirefoxProfiles: firefoxProfiles,
		StatePath:       sp,
		DryRun:          dryRun,
		AllowEmpty:      allowEmpty,
	}

	certutilPath := resolveNSSPath(nssPath)
	if containsList(browsers, "firefox") {
		if _, err := os.Stat(certutilPath); err != nil {
			return codeError(ExitNSSMissing, fmt.Errorf("未找到 NSS certutil: %s", certutilPath))
		}
	}

	st, err := state.Load(sp)
	if err != nil {
		return codeError(ExitError, err)
	}
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

	res, err := a.deps.ApplyFunc(context.Background(), options, ad)
	if err != nil {
		var ae *apply.Error
		if errors.As(err, &ae) {
			return codeError(ae.Code, ae.Err)
		}
		return codeError(ExitError, err)
	}
	if !dryRun {
		if err := st.Save(sp); err != nil {
			return codeError(ExitError, err)
		}
	}
	fmt.Fprintln(a.stdout, "added:", res.Added, "skipped:", res.Skipped, "failed:", res.Failed)
	if len(res.SkippedProfiles) > 0 {
		return codeError(ExitFirefoxPrimaryPassword, nil)
	}
	if res.Failed > 0 {
		return codeError(ExitError, nil)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func containsList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
