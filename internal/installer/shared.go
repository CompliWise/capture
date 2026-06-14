package installer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const MaxInstallerLogBytes = 65536

var safeNamePattern = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ThumbprintFromPEM returns lowercase SHA-256 hex of the first certificate block.
func ThumbprintFromPEM(chainPem string) (string, error) {
	trimmed := strings.TrimSpace(chainPem)
	if trimmed == "" {
		return "", fmt.Errorf("certificate chain is empty")
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:])), nil
}

// TruncateLog caps installer log output for deployment reports.
func TruncateLog(log string) string {
	if len(log) <= MaxInstallerLogBytes {
		return log
	}
	return log[:MaxInstallerLogBytes]
}

// ValidatePathWithinBase rejects traversal and ensures target stays under base.
func ValidatePathWithinBase(baseDir, targetPath string) error {
	base := filepath.Clean(strings.TrimSpace(baseDir))
	target := filepath.Clean(strings.TrimSpace(targetPath))

	if strings.Contains(target, "..") {
		return fmt.Errorf("path traversal is not allowed")
	}

	rel, err := filepath.Rel(base, target)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if strings.HasPrefix(rel, "..") {
		return fmt.Errorf("path must stay within %s", base)
	}

	return nil
}

// SanitizeFileName keeps only safe characters for certificate filenames.
func SanitizeFileName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "cert.crt"
	}
	return safeNamePattern.ReplaceAllString(trimmed, "-")
}

// DefaultAlias returns a stable keytool/filesystem alias for an assignment.
func DefaultAlias(assignmentID, configured string) string {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed
	}
	if trimmed := strings.TrimSpace(assignmentID); trimmed != "" {
		return "compliwise-" + trimmed
	}
	return "compliwise-cert"
}
