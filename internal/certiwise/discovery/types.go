package discovery

import (
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

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
	VerifyEndpoint string
}

// TLSListenerTarget is one host:port pair to probe for TLS listeners.
type TLSListenerTarget struct {
	Host string
	Port int
}

// TLSListenerOptions configures TLS listener port scanning.
type TLSListenerOptions struct {
	Enabled             bool
	Hosts               []string
	StaticPorts         []int
	StaticPortsExplicit bool
	PortRange           string
	Timeout             time.Duration
	Insecure            bool
	MaxWorkers          int
	Assignments         []certiwise.AssignmentPullItem
}

// ScanOptions configures a discovery scan run.
type ScanOptions struct {
	PemPaths    []string
	MaxItems    int
	Assignments []AssignmentRef
	TLSListener TLSListenerOptions
}
