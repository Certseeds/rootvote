package platform

import "testing"

func TestParseScope(t *testing.T) {
	for _, in := range []string{"user", "machine", "all"} {
		if _, err := ParseScope(in); err != nil {
			t.Fatalf("ParseScope(%q) error: %v", in, err)
		}
	}
	if _, err := ParseScope("bad"); err == nil {
		t.Fatal("want error")
	}
}
