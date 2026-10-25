package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/nssprofile"
	"github.com/Certseeds/rootvote/internal/platform"
)

func resolveNSSPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	dir, err := platform.ExeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "tools", "nss", "certutil"+platform.ExeSuffix())
}

func (a *app) newDoctorCmd() *cobra.Command {
	var manifestPath, nssPath string
	var cert9Paths rawMultiFlag
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "环境检查",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runDoctor(manifestPath, nssPath, cert9Paths)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "清单目录")
	cmd.Flags().StringVar(&nssPath, "nss-certutil", "", "NSS certutil 路径")
	cmd.Flags().Var(&cert9Paths, "cert9-path", "追加 <app>:<cert9.db 完整路径>")
	return cmd
}

func (a *app) runDoctor(manifestPath, nssPath string, cert9Paths rawMultiFlag) error {
	dir := manifestPath
	if dir == "" {
		dir = defaultManifestDir()
	}

	failed := 0
	check := func(ok bool, label, detail string) {
		if ok {
			fmt.Fprintln(a.stdout, "[OK]  ", label, detail)
			return
		}
		failed++
		fmt.Fprintln(a.stdout, "[FAIL]", label, detail)
	}

	statePath, err := platform.StatePathForScope(platform.ScopeUser)
	check(err == nil, "状态文件路径", fmt.Sprint(statePath, err))
	if err == nil {
		err = os.MkdirAll(filepath.Dir(statePath), 0o700)
		check(err == nil, "状态目录可写", filepath.Dir(statePath))
	}

	if _, err := manifest.Verify(dir); err != nil {
		check(false, "清单校验", err.Error())
	} else {
		check(true, "清单校验", dir)
	}

	path := resolveNSSPath(nssPath)
	_, statErr := os.Stat(path)
	check(statErr == nil && path != "", "NSS certutil", path)
	if statErr == nil && path != "" {
		ct := nss.New(path)
		runErr := ct.Check(context.Background())
		detail := path
		if runErr != nil {
			detail = fmt.Sprint(path, " ", runErr)
		}
		check(runErr == nil, "NSS certutil 可执行", detail)
	}

	extra, err := nssprofile.GroupCert9Paths(cert9Paths)
	if err != nil {
		check(false, "--cert9-path", err.Error())
	}
	counts := make(map[nssprofile.App]int)
	for _, target := range platform.DefaultTargets() {
		app := nssprofile.App(target)
		if !app.Valid() {
			continue
		}
		profiles, warnings, err := discoverApp(app, extra[app])
		if err != nil {
			check(false, string(app)+" profile", err.Error())
			continue
		}
		counts[app] = len(profiles)
		for _, w := range warnings {
			fmt.Fprintln(a.stdout, "[WARN]", w)
		}
	}
	for _, app := range []nssprofile.App{nssprofile.AppFirefox, nssprofile.AppThunderbird, nssprofile.AppChromium} {
		if _, ok := counts[app]; !ok {
			continue
		}
		check(counts[app] > 0, string(app)+" profile", fmt.Sprint(counts[app], " 个"))
	}

	if stores, err := platform.Open(platform.ScopeUser); err != nil {
		check(false, "CurrentUser 存储", err.Error())
	} else {
		for _, s := range stores {
			s.Close()
		}
		check(true, "CurrentUser 存储", "可访问")
	}

	if failed > 0 {
		return codeError(ExitError, nil)
	}
	return nil
}
