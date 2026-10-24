package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/manifest"
	"github.com/Certseeds/rootvote/internal/platform"
)

func defaultManifestDir() string {
	dir, err := platform.DefaultManifestDir()
	if err != nil {
		return "./blacklist"
	}
	return dir
}

func (a *app) newDisplayCmd() *cobra.Command {
	var manifestPath string
	var asJSON, verbose, verify bool
	cmd := &cobra.Command{
		Use:   "display",
		Short: "查看清单",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runDisplay(manifestPath, asJSON, verbose, verify)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "", "清单目录")
	cmd.Flags().BoolVar(&asJSON, "json", false, "输出 JSON")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "显示完整 SHA-256 和 issuer")
	cmd.Flags().BoolVar(&verify, "verify", false, "校验清单完整性")
	return cmd
}

func (a *app) runDisplay(manifestPath string, asJSON, verbose, verify bool) error {
	dir := manifestPath
	if dir == "" {
		dir = defaultManifestDir()
	}

	var m *manifest.Manifest
	var err error
	if verify {
		m, err = manifest.Verify(dir)
	} else {
		m, err = manifest.Read(dir)
	}
	if err != nil {
		return codeError(ExitManifestInvalid, err)
	}

	if asJSON {
		enc := json.NewEncoder(a.stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m); err != nil {
			return codeError(ExitError, err)
		}
		return nil
	}

	fmt.Fprintln(a.stdout, "清单:", dir)
	fmt.Fprintln(a.stdout, "CCADB:", m.CCADBSnapshot)
	fmt.Fprintln(a.stdout, "生成时间:", m.GeneratedAt)
	fmt.Fprintln(a.stdout, "总计:", m.Summary.Total, "根:", m.Summary.Roots, "中间:", m.Summary.Intermediates)
	fmt.Fprintln(a.stdout, "SHA256 | COUNTRY | OWNER | TYPE | SUBJECT")
	for _, e := range m.Entries {
		sha := e.SHA256
		if !verbose && len(sha) > 12 {
			sha = sha[:12]
		}
		subject := e.Subject
		if verbose {
			subject = subject + " | issuer=" + e.Issuer
		}
		fmt.Fprintln(a.stdout, strings.Join([]string{sha, e.Country, e.Owner, e.RecordType, subject}, " | "))
	}
	return nil
}
