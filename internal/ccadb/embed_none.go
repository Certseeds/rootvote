//go:build !embeddata

package ccadb

func loadEmbedded() ([]byte, string, error) {
	return nil, "", ErrNoEmbeddedData
}
