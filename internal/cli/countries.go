package cli

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/Certseeds/rootvote/internal/ccadb"
	"github.com/Certseeds/rootvote/internal/country"
)

type countryRow struct {
	Name  string `json:"name"`
	Code  string `json:"code"`
	Count int    `json:"count"`
}

func (a *app) newCountriesCmd() *cobra.Command {
	var asJSON bool
	var dataPath string
	cmd := &cobra.Command{
		Use:   "countries",
		Short: "列出内嵌数据中的国家/地区",
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runCountries(asJSON, dataPath)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "输出 JSON")
	cmd.Flags().StringVar(&dataPath, "data", "", "覆盖内嵌数据文件")
	return cmd
}

func (a *app) runCountries(asJSON bool, dataPath string) error {
	var records []ccadb.Record
	var err error
	if dataPath != "" {
		records, err = ccadb.LoadFile(dataPath)
	} else {
		records, _, err = a.deps.LoadData()
	}
	if err != nil {
		return codeError(ExitError, err)
	}

	counts := ccadb.CountryCounts(records)
	rows := make([]countryRow, 0, len(counts))
	for name, count := range counts {
		rows = append(rows, countryRow{Name: name, Code: country.CodeForName(name), Count: count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Code != rows[j].Code {
			return rows[i].Code < rows[j].Code
		}
		return rows[i].Name < rows[j].Name
	})

	if asJSON {
		enc := json.NewEncoder(a.stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return codeError(ExitError, err)
		}
		return nil
	}

	fmt.Fprintln(a.stdout, "CODE | COUNTRY | CERTS")
	for _, r := range rows {
		code := r.Code
		if code == "" {
			code = "-"
		}
		fmt.Fprintln(a.stdout, code, "|", r.Name, "|", r.Count)
	}
	return nil
}
