package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/firefox"
	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nss"
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
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "环境检查",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runDoctor(manifestPath, nssPath)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "清单目录")
	cmd.Flags().StringVar(&nssPath, "nss-certutil", "", "NSS certutil 路径")
	return cmd
}

func (a *app) runDoctor(manifestPath, nssPath string) error {
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

	statePath, err := platform.StatePath()
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
	check(statErr == nil, "NSS certutil", path)
	if statErr == nil {
		ct := nss.New(path)
		_, _, runErr := ct.Exec.Run(context.Background(), path, "-H")
		check(runErr == nil, "NSS certutil 可执行", path)
	}

	if dataDir, err := platform.FirefoxDataDir(); err == nil {
		profiles, warnings, _ := firefox.Discover(dataDir, nil)
		check(len(profiles) > 0, "Firefox profile", fmt.Sprint(len(profiles), " 个"))
		for _, w := range warnings {
			fmt.Fprintln(a.stdout, "[WARN]", w)
		}
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
