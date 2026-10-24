//go:build embeddata

package ccadb

import (
	"embed"
	"strings"
)

//go:embed data.zst snapshot.txt
var embedded embed.FS

func loadEmbedded() ([]byte, string, error) {
	b, err := embedded.ReadFile("data.zst")
	if err != nil {
		return nil, "", err
	}
	s, err := embedded.ReadFile("snapshot.txt")
	if err != nil {
		return nil, "", err
	}
	return b, strings.TrimSpace(string(s)), nil
}
