package ccadb

import "sort"

func Filter(records []Record, countryNames map[string]bool, rootsOnly bool) []Record {
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if !countryNames[r.Country] {
			continue
		}
		if rootsOnly && r.RecordType != RecordRoot {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Country != out[j].Country {
			return out[i].Country < out[j].Country
		}
		if out[i].Owner != out[j].Owner {
			return out[i].Owner < out[j].Owner
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

func CountryCounts(records []Record) map[string]int {
	m := make(map[string]int)
	for _, r := range records {
		m[r.Country]++
	}
	return m
}
