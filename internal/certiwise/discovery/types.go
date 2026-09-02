package discovery

import (
	"time"

	"github.com/compliwise/capture/internal/certiwise"
)

const (
	SourceJavaCacerts      = "java_cacerts"
	SourceWindowsCertStore = "windows_cert_store"
)

// JavaScanOptions configures Java cacerts discovery.
type JavaScanOptions struct {
	Enabled       bool
	MaxJvms       int
	StorePassword string
}

// WindowsScanOptions configures Windows certificate store discovery.
type WindowsScanOptions struct {
	Enabled   bool
	IncludeMy bool
	Executor  CommandExecutor
}

// ScanMetadata carries optional discovery.scan payload metadata.
type ScanMetadata struct {
	JavaCacertsTruncated  bool `json:"javaCacertsTruncated,omitempty"`
	JavaCacertsJvmTotal   int  `json:"javaCacertsJvmTotal,omitempty"`
	JavaCacertsJvmScanned int  `json:"javaCacertsJvmScanned,omitempty"`
}

// ScanResult is the merged output of all discovery scanners.
type ScanResult struct {
	Items    []DiscoveredItem
	Metadata ScanMetadata
}

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
	SkipLinuxCA bool
	Assignments []AssignmentRef
	TLSListener TLSListenerOptions
	Java        JavaScanOptions
	Windows     WindowsScanOptions
}
