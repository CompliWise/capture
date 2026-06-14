package installer

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// ParsePrivateKeyFromPEM parses PKCS#8 or PKCS#1 private key PEM.
func ParsePrivateKeyFromPEM(keyPem string) (crypto.PrivateKey, error) {
	trimmed := strings.TrimSpace(keyPem)
	if trimmed == "" {
		return nil, fmt.Errorf("private key is empty")
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block == nil {
		return nil, fmt.Errorf("no private key block found")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs1 private key: %w", err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ec private key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
}

// ValidateKeyMatchesCert ensures the private key matches the leaf certificate.
func ValidateKeyMatchesCert(chainPem, keyPem string) error {
	leaf, err := parseLeafCertificate(chainPem)
	if err != nil {
		return err
	}

	privateKey, err := ParsePrivateKeyFromPEM(keyPem)
	if err != nil {
		return NewCodedError("ERR_KEY_MISMATCH", "private key does not match certificate")
	}

	if !publicKeysMatch(leaf, privateKey) {
		return NewCodedError("ERR_KEY_MISMATCH", "private key does not match certificate")
	}

	return nil
}

func parseLeafCertificate(chainPem string) (*x509.Certificate, error) {
	trimmed := strings.TrimSpace(chainPem)
	if trimmed == "" {
		return nil, fmt.Errorf("certificate chain is empty")
	}

	rest := []byte(trimmed)
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}

	return nil, fmt.Errorf("no certificate block found")
}

func publicKeysMatch(cert *x509.Certificate, privateKey crypto.PrivateKey) bool {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return false
	}

	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false
	}

	return bytes.Equal(certPubDER, keyPubDER)
}

// ParseFileMode parses an octal permission string such as "0600".
func ParseFileMode(octal string, defaultMode os.FileMode) os.FileMode {
	trimmed := strings.TrimSpace(octal)
	if trimmed == "" {
		return defaultMode
	}

	value, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil {
		return defaultMode
	}

	return os.FileMode(value)
}

// AtomicWriteFile writes content atomically with the given permission mode.
func AtomicWriteFile(path, content string, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	payload := []byte(strings.TrimSpace(content) + "\n")

	if err := os.WriteFile(tmpPath, payload, mode); err != nil {
		_ = os.Remove(tmpPath)
		return NewCodedError(
			"ERR_WRITE_FAILED",
			fmt.Sprintf("failed to write %s: %v", filepath.Base(path), err),
		)
	}

	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return NewCodedError(
			"ERR_WRITE_FAILED",
			fmt.Sprintf("failed to write %s: %v", filepath.Base(path), err),
		)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return NewCodedError(
			"ERR_WRITE_FAILED",
			fmt.Sprintf("failed to write %s: %v", filepath.Base(path), err),
		)
	}

	return nil
}
