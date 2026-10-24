package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/ccadb"
	"github.com/Certseeds/rootvote/internal/country"
	"github.com/Certseeds/rootvote/internal/manifest"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*m = append(*m, part)
		}
	}
	return nil
}

func (m *multiFlag) Type() string { return "strings" }

func (a *app) newGenerateCmd() *cobra.Command {
	var countries multiFlag
	var rootsOnly bool
	var out string
	var force bool
	var dataPath string
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "按国家/地区生成拉黑清单",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runGenerate(countries, rootsOnly, out, force, dataPath)
		},
	}
	cmd.Flags().Var(&countries, "countries", "国家/地区,逗号分隔或重复指定")
	cmd.Flags().BoolVar(&rootsOnly, "roots-only", false, "仅纳入根证书")
	cmd.Flags().StringVar(&out, "out", "./blacklist", "输出目录")
	cmd.Flags().BoolVar(&force, "force", false, "覆盖已有目录")
	cmd.Flags().StringVar(&dataPath, "data", "", "覆盖内嵌数据文件")
	return cmd
}

func (a *app) runGenerate(countries multiFlag, rootsOnly bool, out string, force bool, dataPath string) error {
	if len(countries) == 0 {
		return codeError(ExitUsage, fmt.Errorf("--countries 必填"))
	}
	if !force && dirNotEmpty(out) {
		return codeError(ExitUsage, fmt.Errorf("输出目录非空,使用 --force 覆盖: %s", out))
	}

	names := make(map[string]bool)
	var codes []string
	for _, token := range countries {
		code, ns, err := country.Resolve(token)
		if err != nil {
			return codeError(ExitUsage, err)
		}
		if !contains(codes, code) {
			codes = append(codes, code)
		}
		for _, n := range ns {
			names[n] = true
		}
	}
	sort.Strings(codes)

	var records []ccadb.Record
	var snapshot string
	var err error
	if dataPath != "" {
		records, err = ccadb.LoadFile(dataPath)
		snapshot = "v1.20260101.000000"
	} else {
		records, snapshot, err = a.deps.LoadData()
	}
	if err != nil {
		return codeError(ExitError, err)
	}

	filtered := ccadb.Filter(records, names, rootsOnly)
	recordTypes := []string{ccadb.RecordRoot, ccadb.RecordIntermediate}
	if rootsOnly {
		recordTypes = []string{ccadb.RecordRoot}
	}
	filter := manifest.Filter{
		Countries:    sortedKeys(names),
		CountryCodes: codes,
		RecordTypes:  recordTypes,
	}
	m, certs, err := manifest.Build(filtered, snapshot, "rootvote "+a.deps.Version, filter)
	if err != nil {
		return codeError(ExitError, err)
	}
	if err := manifest.Write(out, m, certs); err != nil {
		return codeError(ExitError, err)
	}
	fmt.Fprintln(a.stdout, "生成清单:", out)
	fmt.Fprintln(a.stdout, "总计:", m.Summary.Total, "根:", m.Summary.Roots, "中间:", m.Summary.Intermediates)
	return nil
}

func dirNotEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
