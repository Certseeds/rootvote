package country

import "testing"

func TestResolveCodeExpandsAliases(t *testing.T) {
	code, names, err := Resolve("us")
	if err != nil {
		t.Fatal(err)
	}
	if code != "US" {
		t.Fatalf("code = %q, want US", code)
	}
	want := map[string]bool{
		"United States of America": true,
		"United States":            true,
		"USA":                      true,
		"US":                       true,
	}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %d entries", names, len(want))
	}
	for _, n := range names {
		if !want[n] {
			t.Fatalf("unexpected alias %q", n)
		}
	}
}

func TestResolveFullName(t *testing.T) {
	code, names, err := Resolve("中国")
	if err != nil {
		t.Fatal(err)
	}
	if code != "CN" {
		t.Fatalf("code = %q, want CN", code)
	}
	found := false
	for _, n := range names {
		if n == "China" {
			found = true
		}
	}
	if !found {
		t.Fatalf("names = %v, want China", names)
	}
}

func TestResolveUnknown(t *testing.T) {
	if _, _, err := Resolve("Atlantis"); err == nil {
		t.Fatal("want error for unknown country")
	}
	if _, _, err := Resolve("ZZ"); err == nil {
		t.Fatal("want error for unknown ISO code")
	}
}

func TestAllSorted(t *testing.T) {
	all := All()
	if len(all) != 60 {
		t.Fatalf("len(All()) = %d, want 60", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Code >= all[i].Code {
			t.Fatalf("not sorted at %d: %s >= %s", i, all[i-1].Code, all[i].Code)
		}
	}
}

func TestCodeForName(t *testing.T) {
	if got := CodeForName("Polska"); got != "PL" {
		t.Fatalf("CodeForName(Polska) = %q, want PL", got)
	}
	if got := CodeForName("Unknown"); got != "" {
		t.Fatalf("CodeForName(Unknown) = %q, want empty", got)
	}
}
