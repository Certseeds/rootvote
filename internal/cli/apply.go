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
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/nssprofile"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

func (a *app) newApplyCmd() *cobra.Command {
	var manifestPath, scopeStr, targetsStr, browsersStr, statePath, nssPath string
	var cert9Paths, firefoxProfiles rawMultiFlag
	var dryRun, yes, allowEmpty bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "应用清单",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runApply(manifestPath, scopeStr, targetsStr, browsersStr, cert9Paths, firefoxProfiles, statePath, nssPath, dryRun, yes, allowEmpty)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "清单目录")
	cmd.Flags().StringVar(&scopeStr, "scope", "user", "user/machine/all")
	cmd.Flags().StringVar(&targetsStr, "targets", "", "逗号分隔的 target,默认随平台")
	cmd.Flags().StringVar(&browsersStr, "browsers", "", "已弃用,等价于 --targets")
	_ = cmd.Flags().MarkHidden("browsers")
	cmd.Flags().Var(&cert9Paths, "cert9-path", "追加 <app>:<cert9.db 完整路径>")
	cmd.Flags().Var(&firefoxProfiles, "firefox-profile", "追加 Firefox profile 目录")
	_ = cmd.Flags().MarkHidden("firefox-profile")
	cmd.Flags().StringVar(&statePath, "state", "", "状态文件")
	cmd.Flags().StringVar(&nssPath, "nss-certutil", "", "NSS certutil 路径")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "只显示计划")
	cmd.Flags().BoolVar(&yes, "yes", false, "跳过确认")
	cmd.Flags().BoolVar(&allowEmpty, "allow-empty", false, "允许空清单")
	return cmd
}

func (a *app) runApply(manifestPath, scopeStr, targetsStr, browsersStr string, cert9Paths, firefoxProfiles rawMultiFlag, statePath, nssPath string, dryRun, yes, allowEmpty bool) error {
	if !dryRun && !yes {
		if !a.deps.IsTTY() {
			return codeError(ExitUsage, errors.New("非交互环境需要 --yes"))
		}
		if !a.deps.Confirm("继续应用清单? [y/N] ") {
			return codeError(ExitError, errors.New("已取消"))
		}
	}

	scope, err := platform.ParseScope(scopeStr)
	if err != nil {
		return codeError(ExitUsage, err)
	}
	targets, err := resolveTargets(targetsStr, browsersStr, scope)
	if err != nil {
		return codeError(ExitUsage, err)
	}
	if err := platform.ValidateTargets(scope, targets); err != nil {
		return codeError(ExitUsage, err)
	}

	dir := manifestPath
	if dir == "" {
		dir = defaultManifestDir()
	}
	sp := statePath
	if sp == "" {
		p, err := platform.StatePathForScope(scope)
		if err != nil {
			return codeError(ExitError, err)
		}
		sp = p
	}

	certutilPath := resolveNSSPath(nssPath)
	if hasNSSApp(targets) {
		if certutilPath == "" {
			return codeError(ExitNSSMissing, fmt.Errorf("未找到 NSS certutil;Linux 可安装 libnss3-tools"))
		}
		if _, err := os.Stat(certutilPath); err != nil {
			return codeError(ExitNSSMissing, fmt.Errorf("未找到 NSS certutil: %s", certutilPath))
		}
	}

	st, err := state.Load(sp)
	if err != nil {
		if os.IsPermission(err) {
			return codeError(ExitPermission, err)
		}
		return codeError(ExitError, err)
	}
	options := apply.Options{
		ManifestDir: dir,
		Scope:       scope,
		Targets:     targets,
		Cert9Paths:  cert9PathsFromFlags(cert9Paths, firefoxProfiles),
		StatePath:   sp,
		DryRun:      dryRun,
		AllowEmpty:  allowEmpty,
	}
	ad := apply.Deps{
		OpenStores:       platform.Open,
		DiscoverProfiles: discoverApp,
		IsRunning:        nssprofile.IsRunning,
		Certutil:         nss.New(certutilPath),
		State:            st,
		Now:              time.Now,
		Out:              a.stdout,
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
			if os.IsPermission(err) {
				return codeError(ExitPermission, err)
			}
			return codeError(ExitError, err)
		}
	}
	for _, tr := range res.Targets {
		fmt.Fprintf(a.stdout, "%s: added %d skipped %d failed %d\n", tr.Name, tr.Added, tr.Skipped, tr.Failed)
	}
	fmt.Fprintf(a.stdout, "total: added %d skipped %d failed %d\n", res.Added, res.Skipped, res.Failed)
	if len(res.SkippedProfiles) > 0 {
		return codeError(ExitPrimaryPassword, nil)
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
