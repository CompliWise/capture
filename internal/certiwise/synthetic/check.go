package synthetic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxErrorMessageLen = 2048

// RunCheck executes one HTTPS GET probe against the monitor URL.
func RunCheck(ctx context.Context, monitor Monitor, userAgent string) CheckResult {
	result := CheckResult{Status: StatusUp}

	timeout := time.Duration(monitor.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var peerCerts []*x509.Certificate
	var negotiatedVersion uint16
	tlsConfig := &tls.Config{
		MinVersion:         tlsMinVersion(monitor.Assertions.MinTLSVersion),
		ServerName:         serverNameFromURL(monitor.URL),
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			peerCerts = parsePeerCertificates(rawCerts)
			return nil
		},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, monitor.URL, nil)
	if err != nil {
		return downResult(result, fmt.Sprintf("invalid monitor URL: %v", err))
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	started := time.Now()
	resp, err := client.Do(req)
	result.ResponseTimeMs = int(time.Since(started).Milliseconds())

	if err != nil {
		return downResult(result, err.Error())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	result.HTTPStatusCode = resp.StatusCode

	if tlsState := resp.TLS; tlsState != nil {
		negotiatedVersion = tlsState.Version
		if len(tlsState.PeerCertificates) > 0 {
			peerCerts = tlsState.PeerCertificates
		}
	}
	applyCertFields(&result, peerCerts)

	failures := evaluateAssertions(monitor, result, peerCerts, negotiatedVersion)
	if len(failures) == 0 {
		result.Status = StatusUp
		result.ErrorMessage = ""
		return result
	}

	result.Status = worstStatus(failures)
	result.ErrorMessage = truncateError(strings.Join(failures, "; "), maxErrorMessageLen)
	return result
}

func evaluateAssertions(
	monitor Monitor,
	result CheckResult,
	peerCerts []*x509.Certificate,
	negotiatedVersion uint16,
) []string {
	var failures []string
	assertions := monitor.Assertions

	if assertions.MinTLSVersion != "" && negotiatedVersion > 0 {
		required := tlsMinVersion(assertions.MinTLSVersion)
		if negotiatedVersion < required {
			failures = append(failures, fmt.Sprintf(
				"TLS version %s is below minimum %s",
				tlsVersionLabel(negotiatedVersion),
				assertions.MinTLSVersion,
			))
		}
	}

	if assertions.ExpectHTTPStatus > 0 && result.HTTPStatusCode != assertions.ExpectHTTPStatus {
		failures = append(failures, fmt.Sprintf(
			"HTTP status %d does not match expected %d",
			result.HTTPStatusCode,
			assertions.ExpectHTTPStatus,
		))
	}

	if assertions.MaxResponseTimeMs > 0 && result.ResponseTimeMs > assertions.MaxResponseTimeMs {
		failures = append(failures, fmt.Sprintf(
			"response time %dms exceeds max %dms",
			result.ResponseTimeMs,
			assertions.MaxResponseTimeMs,
		))
	}

	if len(assertions.ExpectedSan) > 0 {
		var sanNames []string
		if len(peerCerts) > 0 {
			sanNames = certSANNames(peerCerts[0])
		}
		if !sanMatches(sanNames, assertions.ExpectedSan) {
			failures = append(failures, "certificate SAN does not match expected values")
		}
	}

	if assertions.MaxDaysUntilExpiry > 0 && result.CertDaysRemaining >= 0 {
		if result.CertDaysRemaining <= assertions.MaxDaysUntilExpiry {
			failures = append(failures, fmt.Sprintf(
				"certificate expires in %d days (max allowed %d)",
				result.CertDaysRemaining,
				assertions.MaxDaysUntilExpiry,
			))
		}
	}

	return failures
}

func worstStatus(messages []string) string {
	status := StatusUp
	for _, message := range messages {
		next := statusForMessage(message)
		if severity(next) > severity(status) {
			status = next
		}
	}
	return status
}

func statusForMessage(message string) string {
	lower := strings.ToLower(message)
	if strings.Contains(lower, "http status") ||
		strings.Contains(lower, "san") ||
		strings.Contains(lower, "tls") {
		return StatusDown
	}
	if strings.Contains(lower, "response time") || strings.Contains(lower, "expires") {
		return StatusDegraded
	}
	return StatusDown
}

func severity(status string) int {
	switch status {
	case StatusDown:
		return 2
	case StatusDegraded:
		return 1
	default:
		return 0
	}
}

func applyCertFields(result *CheckResult, certs []*x509.Certificate) {
	if len(certs) == 0 {
		result.CertDaysRemaining = -1
		return
	}

	leaf := certs[0]
	if leaf == nil {
		result.CertDaysRemaining = -1
		return
	}

	notAfter := leaf.NotAfter.UTC()
	result.CertExpiresAt = notAfter.Format(time.RFC3339)
	days := int(notAfter.Sub(time.Now().UTC()).Hours() / 24)
	result.CertDaysRemaining = days
}

func sanMatches(names []string, expected []string) bool {
	if len(expected) == 0 {
		return true
	}
	normalized := make(map[string]struct{}, len(names))
	for _, name := range names {
		normalized[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	for _, want := range expected {
		if _, ok := normalized[strings.ToLower(strings.TrimSpace(want))]; ok {
			return true
		}
	}
	return false
}

func certSANNames(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	names := append([]string{}, cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	return names
}

func parsePeerCertificates(rawCerts [][]byte) []*x509.Certificate {
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

func tlsMinVersion(version string) uint16 {
	switch strings.TrimSpace(version) {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

func tlsVersionLabel(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "unknown"
	}
}

func downResult(result CheckResult, message string) CheckResult {
	result.Status = StatusDown
	result.ErrorMessage = truncateError(message, maxErrorMessageLen)
	return result
}

func truncateError(message string, maxLen int) string {
	if len(message) <= maxLen {
		return message
	}
	if maxLen <= 3 {
		return message[:maxLen]
	}
	return message[:maxLen-3] + "..."
}

func serverNameFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
