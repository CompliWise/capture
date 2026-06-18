package probe

import (
	"crypto/x509"
	"fmt"
	"time"
)

// ProbeTarget is one TLS endpoint to dial.
type ProbeTarget struct {
	URL           string
	Host          string
	Port          int
	ServerName    string
	ApplicationID string
	CertificateID string
	DeploymentID  string
}

// HandshakeOptions configures a TLS probe dial.
type HandshakeOptions struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// HandshakeResult captures TLS connection metadata from a probe dial.
type HandshakeResult struct {
	ServerName  string
	PeerAddress string
	TLSVersion  string
	CipherSuite string
	ChainSHA256 []string
	PeerCerts   []*x509.Certificate
	DurationMs  int
	DialError   error
}

// ProbeResult is the full outcome of probing one target.
type ProbeResult struct {
	ServerName              string
	PeerAddress             string
	TLSVersion              string
	CipherSuite             string
	PresentedChainSha256    []string
	PresentedChainSubjectCN []string
	ValidationResult        string
	ValidationErrors        []string
	DurationMs              int
}

// ValidationOutcome maps probe results to schema validationResult values.
type ValidationOutcome struct {
	Result        string
	Errors        []string
	VerifiedChain []*x509.Certificate
}

const handshakeErrorThumbprint = "0000000000000000000000000000000000000000000000000000000000000000"

func targetKey(target ProbeTarget) string {
	serverName := target.ServerName
	if serverName == "" {
		serverName = target.Host
	}
	port := target.Port
	if port <= 0 {
		port = 443
	}
	return fmt.Sprintf("%s|%s:%d", serverName, target.Host, port)
}
