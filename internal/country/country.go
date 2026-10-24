package country

import (
	"fmt"
	"sort"
	"strings"
)

type Entry struct {
	Code  string
	Names []string
}

var table = map[string][]string{
	"AE": {"UAE"},
	"AT": {"Austria"},
	"AU": {"Australia"},
	"BD": {"Bangladesh"},
	"BE": {"Belgium"},
	"BG": {"Bulgaria"},
	"BR": {"Brazil", "Brasil"},
	"CA": {"Canada"},
	"CH": {"Switzerland"},
	"CL": {"Chile"},
	"CN": {"China", "中国"},
	"CO": {"Colombia"},
	"CV": {"Cabo Verde"},
	"CZ": {"Czech Republic"},
	"DE": {"Germany"},
	"DK": {"Denmark"},
	"DZ": {"Algeria"},
	"EE": {"Estonia"},
	"ES": {"Spain", "España", "SPAIN"},
	"FI": {"Finland"},
	"FR": {"France"},
	"GB": {"United Kingdom", "United Kingdom of Great Britain and Northern Ireland"},
	"GR": {"Greece"},
	"HK": {"Hong Kong SAR, China"},
	"HR": {"Croatia"},
	"HU": {"Hungary"},
	"ID": {"Indonesia"},
	"IE": {"Ireland"},
	"IL": {"Israel"},
	"IN": {"India"},
	"IT": {"Italy"},
	"JP": {"Japan"},
	"KR": {"Republic of Korea (South Korea)"},
	"LK": {"Sri Lanka"},
	"LT": {"Lithuania"},
	"LU": {"Luxembourg"},
	"LV": {"Latvia"},
	"MX": {"Mexico"},
	"MY": {"Malaysia"},
	"NL": {"Netherlands", "NL"},
	"NO": {"Norway"},
	"PK": {"Pakistan"},
	"PL": {"Polska", "Poland"},
	"PT": {"Portugal"},
	"RO": {"Romania"},
	"RS": {"Serbia"},
	"SA": {"Saudi Arabia"},
	"SD": {"Sudan"},
	"SE": {"Sweden"},
	"SG": {"Singapore"},
	"SI": {"Slovenia"},
	"SK": {"Slovakia"},
	"TH": {"Thailand"},
	"TN": {"Tunisia"},
	"TR": {"Turkey"},
	"TW": {"Taiwan, China"},
	"US": {"United States of America", "United States", "USA", "US"},
	"UY": {"Uruguay"},
	"VE": {"Venezuela"},
	"ZA": {"South Africa"},
}

var byName = make(map[string]string)

func init() {
	for code, names := range table {
		for _, name := range names {
			byName[strings.ToLower(name)] = code
		}
	}
}

func Resolve(token string) (string, []string, error) {
	t := strings.TrimSpace(token)
	if t == "" {
		return "", nil, fmt.Errorf("国家/地区不能为空")
	}
	if len(t) == 2 {
		code := strings.ToUpper(t)
		names, ok := table[code]
		if !ok {
			return "", nil, fmt.Errorf("未知的 ISO 代码 %q;运行 rootvote countries 查看可选值", t)
		}
		return code, append([]string(nil), names...), nil
	}
	code, ok := byName[strings.ToLower(t)]
	if !ok {
		return "", nil, fmt.Errorf("未识别的国家/地区 %q;运行 rootvote countries 查看可选值", t)
	}
	return code, append([]string(nil), table[code]...), nil
}

func All() []Entry {
	out := make([]Entry, 0, len(table))
	for code, names := range table {
		out = append(out, Entry{Code: code, Names: append([]string(nil), names...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func CodeForName(name string) string {
	return byName[strings.ToLower(strings.TrimSpace(name))]
}
