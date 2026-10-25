package cli

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/nss"
	"github.com/Certseeds/rootvote/internal/nssprofile"
	"github.com/Certseeds/rootvote/internal/platform"
	"github.com/Certseeds/rootvote/internal/state"
)

type statusReport struct {
	ManifestDir string          `json:"manifest_dir"`
	Snapshot    string          `json:"snapshot"`
	Total       int             `json:"total"`
	StatePath   string          `json:"state_path"`
	StateCount  int             `json:"state_count"`
	Stores      []storeStatus   `json:"stores"`
	Profiles    []profileStatus `json:"profiles"`
}

type storeStatus struct {
	Scope   string `json:"scope"`
	Present int    `json:"present"`
	Total   int    `json:"total"`
	Error   string `json:"error,omitempty"`
}

type profileStatus struct {
	App         string `json:"app"`
	Path        string `json:"path"`
	Running     bool   `json:"running"`
	PrimaryPass bool   `json:"primary_password"`
	Rootvote    int    `json:"rootvote_entries"`
	Error       string `json:"error,omitempty"`
}

func (a *app) newStatusCmd() *cobra.Command {
	var manifestPath, statePath, nssPath string
	var cert9Paths rawMultiFlag
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "显示状态",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runStatus(manifestPath, statePath, nssPath, cert9Paths, asJSON)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "清单目录")
	cmd.Flags().StringVar(&statePath, "state", "", "状态文件")
	cmd.Flags().StringVar(&nssPath, "nss-certutil", "", "NSS certutil 路径")
	cmd.Flags().Var(&cert9Paths, "cert9-path", "追加 <app>:<cert9.db 完整路径>")
	cmd.Flags().BoolVar(&asJSON, "json", false, "输出 JSON")
	return cmd
}

func (a *app) runStatus(manifestPath, statePath, nssPath string, cert9Paths rawMultiFlag, asJSON bool) error {
	dir := manifestPath
	if dir == "" {
		dir = defaultManifestDir()
	}
	sp := statePath
	if sp == "" {
		p, err := platform.StatePathForScope(platform.ScopeUser)
		if err != nil {
			return codeError(ExitError, err)
		}
		sp = p
	}

	report := statusReport{ManifestDir: dir, StatePath: sp}
	if m, err := manifest.Verify(dir); err == nil {
		report.Snapshot = m.CCADBSnapshot
		report.Total = m.Summary.Total
		certs, err := manifest.LoadCerts(dir)
		if err == nil {
			for _, scope := range []platform.Scope{platform.ScopeUser, platform.ScopeMachine} {
				st := storeStatus{Scope: string(scope), Total: len(certs)}
				stores, err := platform.Open(scope)
				if err != nil {
					st.Error = err.Error()
					report.Stores = append(report.Stores, st)
					continue
				}
				if len(stores) > 0 {
					for _, certDER := range certs {
						sum := sha1.Sum(certDER)
						ok, err := stores[0].Contains(sum)
						if err != nil {
							st.Error = err.Error()
							break
						}
						if ok {
							st.Present++
						}
					}
				}
				for _, s := range stores {
					s.Close()
				}
				report.Stores = append(report.Stores, st)
			}
		}
	} else {
		report.Snapshot = "invalid manifest"
	}

	if st, err := state.Load(sp); err == nil {
		report.StateCount = len(st.Applied)
	}

	extra, err := nssprofile.GroupCert9Paths(cert9Paths)
	if err != nil {
		return codeError(ExitUsage, err)
	}
	profiles, _, err := discoverDefaults(extra)
	if err != nil {
		return codeError(ExitError, err)
	}
	ct := nss.New(resolveNSSPath(nssPath))
	for _, p := range profiles {
		ps := profileStatus{App: string(p.App), Path: p.Dir, Running: nssprofile.IsRunning(p)}
		if has, err := ct.HasPrimaryPassword(context.Background(), p.Dir); err == nil {
			ps.PrimaryPass = has
		} else {
			ps.Error = err.Error()
		}
		if entries, err := ct.ListEntries(context.Background(), p.Dir); err == nil {
			for _, e := range entries {
				if len(e.Nick) >= len("rootvote:") && e.Nick[:len("rootvote:")] == "rootvote:" {
					ps.Rootvote++
				}
			}
		}
		report.Profiles = append(report.Profiles, ps)
	}

	if asJSON {
		enc := json.NewEncoder(a.stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return codeError(ExitError, err)
		}
		return nil
	}

	fmt.Fprintln(a.stdout, "清单:", report.ManifestDir)
	fmt.Fprintln(a.stdout, "CCADB:", report.Snapshot, "总计:", report.Total)
	fmt.Fprintln(a.stdout, "状态文件:", report.StatePath, "记录数:", report.StateCount)
	for _, s := range report.Stores {
		fmt.Fprintln(a.stdout, "存储:", s.Scope, "已存在:", s.Present, "/", s.Total, s.Error)
	}
	for _, p := range report.Profiles {
		fmt.Fprintln(a.stdout, "NSS:", p.App, p.Path, "运行中:", p.Running, "主密码:", p.PrimaryPass, "rootvote:", p.Rootvote, p.Error)
	}
	return nil
}
