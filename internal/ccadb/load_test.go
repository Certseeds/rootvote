package ccadb

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func makeZstdJSONL(t *testing.T, records []Record) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(zw)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLoadFrom(t *testing.T) {
	in := []Record{
		{SHA256: "aa", Owner: "A", Country: "China", RecordType: RecordRoot},
		{SHA256: "bb", Owner: "B", Country: "Japan", RecordType: RecordIntermediate},
	}
	got, err := LoadFrom(bytes.NewReader(makeZstdJSONL(t, in)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].SHA256 != "aa" || got[1].Country != "Japan" {
		t.Fatalf("got %+v", got)
	}
}

func TestFilterByCountryAndType(t *testing.T) {
	records := []Record{
		{SHA256: "1", Country: "China", Owner: "A", RecordType: RecordRoot},
		{SHA256: "2", Country: "China", Owner: "A", RecordType: RecordIntermediate},
		{SHA256: "3", Country: "Japan", Owner: "B", RecordType: RecordRoot},
	}
	got := Filter(records, map[string]bool{"China": true}, false)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	got = Filter(records, map[string]bool{"China": true}, true)
	if len(got) != 1 || got[0].SHA256 != "1" {
		t.Fatalf("got %+v", got)
	}
}

func TestFilterSortsDeterministically(t *testing.T) {
	records := []Record{
		{SHA256: "z", Country: "China", Owner: "B"},
		{SHA256: "a", Country: "China", Owner: "A"},
		{SHA256: "m", Country: "China", Owner: "A"},
	}
	got := Filter(records, map[string]bool{"China": true}, false)
	want := []string{"a", "m", "z"}
	for i, w := range want {
		if got[i].SHA256 != w {
			t.Fatalf("got[%d] = %s, want %s", i, got[i].SHA256, w)
		}
	}
}
