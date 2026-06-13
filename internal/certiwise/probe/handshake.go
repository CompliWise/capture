package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeHandshake dials a TLS endpoint and extracts connection metadata.
func ProbeHandshake(
	ctx context.Context,
	target ProbeTarget,
	opts HandshakeOptions,
) HandshakeResult {
	started := time.Now()
	result := HandshakeResult{
		ServerName: target.ServerName,
	}

	if result.ServerName == "" {
		result.ServerName = target.Host
	}

	dialer := &net.Dialer{Timeout: opts.Timeout}
	tlsConfig := &tls.Config{
		ServerName:         result.ServerName,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	address := PeerAddressForTarget(target)
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	result.DurationMs = int(time.Since(started).Milliseconds())

	if err != nil {
		result.DialError = err
		result.PeerAddress = address
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.PeerAddress = conn.RemoteAddr().String()
	result.TLSVersion = tlsVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.PeerCerts = state.PeerCertificates
	result.PeerCerts = state.PeerCertificates
	result.ChainSHA256 = chainThumbprints(state.PeerCertificates)

	if ctx.Err() != nil {
		result.DialError = ctx.Err()
	}

	return result
}

func chainThumbprints(certs []*x509.Certificate) []string {
	if len(certs) == 0 {
		return nil
	}

	out := make([]string, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		out = append(out, strings.ToLower(hex.EncodeToString(sum[:])))
	}
	return out
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("TLS%x", version)
	}
}

// PlaceholderChainSHA256 returns a deterministic thumbprint when no chain is available.
func PlaceholderChainSHA256(target ProbeTarget) string {
	sum := sha256.Sum256([]byte("probe-failed:" + targetKey(target)))
	return strings.ToLower(hex.EncodeToString(sum[:]))
}
