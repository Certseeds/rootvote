package ccadb

const (
	RecordRoot         = "Root Certificate"
	RecordIntermediate = "Intermediate Certificate"
)

type Record struct {
	SHA256     string `json:"sha256"`
	Owner      string `json:"owner"`
	Country    string `json:"country"`
	CertName   string `json:"cert_name"`
	RecordType string `json:"record_type"`
	TLSCapable bool   `json:"tls_capable"`
	Status     string `json:"status"`
	PEM        string `json:"pem"`
}
