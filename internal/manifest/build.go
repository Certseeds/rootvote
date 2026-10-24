package manifest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Certseeds/rootvote/internal/ccadb"
)

func Build(records []ccadb.Record, snapshot, generator string, filter Filter) (*Manifest, map[string][]byte, error) {
	generatedAt, err := SnapshotTime(snapshot)
	if err != nil {
		return nil, nil, err
	}
	if filter.Countries == nil {
		filter.Countries = []string{}
	}
	if filter.CountryCodes == nil {
		filter.CountryCodes = []string{}
	}
	if filter.RecordTypes == nil {
		filter.RecordTypes = []string{}
	}

	entries := make([]Entry, 0, len(records))
	certs := make(map[string][]byte, len(records))
	roots, intermediates := 0, 0
	for _, r := range records {
		block, _ := pem.Decode([]byte(r.PEM))
		if block == nil {
			return nil, nil, fmt.Errorf("%s: PEM 解码失败", r.SHA256)
		}
		sum := sha256.Sum256(block.Bytes)
		actual := hex.EncodeToString(sum[:])
		if !strings.EqualFold(actual, r.SHA256) {
			return nil, nil, fmt.Errorf("%s: 证书指纹不匹配(%s)", r.SHA256, actual)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: 解析 X.509: %w", r.SHA256, err)
		}
		if want := filter.SubjectCountryCodes[r.Country]; want != "" && len(cert.Subject.Country) > 0 {
			matched := false
			for _, c := range cert.Subject.Country {
				if strings.EqualFold(c, want) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		entries = append(entries, Entry{
			SHA256:          actual,
			Subject:         cert.Subject.String(),
			Issuer:          cert.Issuer.String(),
			Owner:           r.Owner,
			Country:         r.Country,
			CertificateName: r.CertName,
			RecordType:      r.RecordType,
			TLSCapable:      r.TLSCapable,
			NotBefore:       cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:        cert.NotAfter.UTC().Format(time.RFC3339),
			File:            CertPath(actual),
		})
		certs[actual] = []byte(r.PEM)
		if r.RecordType == ccadb.RecordRoot {
			roots++
		} else {
			intermediates++
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Country != b.Country {
			return a.Country < b.Country
		}
		if a.Owner != b.Owner {
			return a.Owner < b.Owner
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.SHA256 < b.SHA256
	})
	m := &Manifest{
		Schema:        Schema,
		GeneratedAt:   generatedAt.Format(time.RFC3339),
		CCADBSnapshot: snapshot,
		Generator:     generator,
		Filter:        filter,
		Summary: Summary{
			Total:         len(entries),
			Roots:         roots,
			Intermediates: intermediates,
		},
		Entries: entries,
	}
	return m, certs, nil
}
