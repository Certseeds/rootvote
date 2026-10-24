package ccadb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

var ErrNoEmbeddedData = fmt.Errorf("当前二进制未内嵌 CCADB 数据;请使用 release 版或 --data")

func LoadFrom(r io.Reader) ([]Record, error) {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("打开 zstd 流: %w", err)
	}
	defer zr.Close()

	dec := json.NewDecoder(zr)
	var out []Record
	for {
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("解析 JSONL: %w", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func LoadFile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadFrom(f)
}

func Load() ([]Record, string, error) {
	b, snapshot, err := loadEmbedded()
	if err != nil {
		return nil, "", err
	}
	records, err := LoadFrom(bytes.NewReader(b))
	if err != nil {
		return nil, "", err
	}
	return records, snapshot, nil
}
