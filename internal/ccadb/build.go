package ccadb

import (
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
)

type BuildResult struct {
	Snapshot string
	Count    int
}

func BuildFromDir(moduleDir, outDir, snapshot string, canonicalCountry func(string) string) (BuildResult, error) {
	pemBySHA, err := readPEMCSVs(filepath.Join(moduleDir, "cmd", "ski_spki", "data", "AllCertificatePEMsCSVFormat_NotBeforeYear_*"))
	if err != nil {
		return BuildResult{}, err
	}
	records, err := readRecordsCSV(filepath.Join(moduleDir, "data", "AllCertificateRecordsCSVFormatV5"), pemBySHA, canonicalCountry)
	if err != nil {
		return BuildResult{}, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].SHA256 < records[j].SHA256 })

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return BuildResult{}, err
	}
	if err := writeJSONLZstd(filepath.Join(outDir, "data.zst"), records); err != nil {
		return BuildResult{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "snapshot.txt"), []byte(snapshot), 0o644); err != nil {
		return BuildResult{}, err
	}
	return BuildResult{Snapshot: snapshot, Count: len(records)}, nil
}

func readPEMCSVs(pattern string) (map[string]string, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("未找到 PEM CSV: %s", pattern)
	}
	out := make(map[string]string)
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		r := csv.NewReader(f)
		r.FieldsPerRecord = -1
		r.LazyQuotes = true
		header, err := r.Read()
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		shaIdx := indexOf(header, "SHA-256 Fingerprint")
		pemIdx := indexOf(header, "X.509 Certificate (PEM)")
		if shaIdx < 0 || pemIdx < 0 {
			f.Close()
			return nil, fmt.Errorf("%s: 缺少必要表头", path)
		}
		for {
			row, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			if len(row) <= shaIdx || len(row) <= pemIdx {
				continue
			}
			sha := strings.ToLower(strings.TrimSpace(row[shaIdx]))
			certPEM := row[pemIdx]
			if sha == "" || certPEM == "" {
				continue
			}
			if block, _ := pem.Decode([]byte(certPEM)); block == nil {
				continue
			}
			out[sha] = certPEM
		}
		f.Close()
	}
	return out, nil
}

func readRecordsCSV(path string, pemBySHA map[string]string, canonicalCountry func(string) string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	shaIdx := indexOf(header, "SHA-256 Fingerprint")
	ownerIdx := indexOf(header, "CA Owner")
	countryIdx := indexOf(header, "Country")
	nameIdx := indexOf(header, "Certificate Name")
	typeIdx := indexOf(header, "Certificate Record Type")
	tlsIdx := indexOf(header, "TLS Capable")
	statusIdx := indexOf(header, "Status of Root Cert")
	for _, idx := range []int{shaIdx, ownerIdx, countryIdx, nameIdx, typeIdx, tlsIdx, statusIdx} {
		if idx < 0 {
			return nil, fmt.Errorf("%s: 缺少必要列", path)
		}
	}

	seen := make(map[string]bool)
	var out []Record
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(row) <= shaIdx {
			continue
		}
		sha := strings.ToLower(strings.TrimSpace(row[shaIdx]))
		certPEM, ok := pemBySHA[sha]
		if !ok || seen[sha] {
			continue
		}
		seen[sha] = true
		country := strings.TrimSpace(row[countryIdx])
		if canonicalCountry != nil {
			country = canonicalCountry(country)
		}
		out = append(out, Record{
			SHA256:     sha,
			Owner:      strings.TrimSpace(row[ownerIdx]),
			Country:    country,
			CertName:   strings.TrimSpace(row[nameIdx]),
			RecordType: strings.TrimSpace(row[typeIdx]),
			TLSCapable: strings.EqualFold(strings.TrimSpace(row[tlsIdx]), "true"),
			Status:     strings.TrimSpace(row[statusIdx]),
			PEM:        certPEM,
		})
	}
	return out, nil
}

func indexOf(header []string, name string) int {
	for i, h := range header {
		if strings.TrimSpace(h) == name {
			return i
		}
	}
	return -1
}

func writeJSONLZstd(path string, records []Record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw, err := zstd.NewWriter(f, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(zw)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			zw.Close()
			return err
		}
	}
	return zw.Close()
}
