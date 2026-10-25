package cli

import (
	"testing"

	"github.com/Certseeds/rootvote/internal/nss"
)

func TestCountRootvote(t *testing.T) {
	entries := []nss.Entry{
		{Nick: "rootvote:abc"},
		{Nick: "NSS Certificate DB:rootvote:def"},
		{Nick: "Other CA"},
	}
	if got := countRootvote(entries); got != 2 {
		t.Fatalf("countRootvote = %d, want 2", got)
	}
}
