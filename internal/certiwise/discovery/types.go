package discovery

// DiscoveredItem is one certificate observed during a discovery scan.
type DiscoveredItem struct {
	Source         string `json:"source"`
	Path           string `json:"path,omitempty"`
	Alias          string `json:"alias,omitempty"`
	Thumbprint     string `json:"thumbprint"`
	SubjectCN      string `json:"subjectCn,omitempty"`
	NotAfter       string `json:"notAfter,omitempty"`
	TrustStoreType string `json:"trustStoreType,omitempty"`
}

// AssignmentRef is a lightweight assignment target for path verification.
type AssignmentRef struct {
	TrustStorePath string
	CertFileName   string
	Alias          string
	TrustStoreType string
}

// ScanOptions configures a discovery scan run.
type ScanOptions struct {
	PemPaths    []string
	MaxItems    int
	Assignments []AssignmentRef
}
