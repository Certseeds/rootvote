package main

import "testing"

func TestCanonicalCountryPassthrough(t *testing.T) {
	if got := canonicalCountry("China"); got != "China" {
		t.Fatalf("canonicalCountry(China) = %q", got)
	}
	if got := canonicalCountry("Unknown"); got != "Unknown" {
		t.Fatalf("canonicalCountry(Unknown) = %q", got)
	}
}
