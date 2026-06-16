package macos

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

// Installer implements macos_keychain_system for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "macos_keychain_system"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	if err := ensurePlatform(opts); err != nil {
		return "", err
	}

	thumbprint, err := installer.ThumbprintFromPEM(opts.ChainPem)
	if err != nil {
		return "", installer.NewCodedError("ERR_INVALID_PEM", "malformed certificate PEM")
	}

	commonName, err := commonNameFromPEM(opts.ChainPem)
	if err != nil {
		return "", installer.NewCodedError("ERR_INVALID_PEM", "malformed certificate PEM")
	}

	keychainPath, err := ResolveKeychainPath(opts.KeychainPath)
	if err != nil {
		return "", err
	}

	exec := resolveExecutor(opts)
	tempPath, cleanup, err := writeTempFile("compliwise-trust", opts.ChainPem)
	if err != nil {
		return "", err
	}
	defer cleanup()

	output, runErr := runSecurity(
		exec,
		"add-trusted-cert",
		"-d",
		"-r",
		"trustRoot",
		"-k",
		keychainPath,
		tempPath,
	)
	logLines := []string{
		fmt.Sprintf("security add-trusted-cert -k %s", keychainPath),
		strings.TrimSpace(string(output)),
	}
	if runErr != nil {
		if mapped := mapSecurityError(output, runErr, thumbprint, opts.Thumbprint); mapped != nil {
			if installer.ErrorCode(mapped) == "ERR_IDEMPOTENT" {
				logLines = append(logLines, "idempotent: certificate already trusted")
			} else {
				return strings.Join(logLines, "\n"), mapped
			}
		} else {
			return strings.Join(logLines, "\n"), fmt.Errorf("%w: %s", runErr, strings.TrimSpace(string(output)))
		}
	}

	if endpoint := strings.TrimSpace(opts.VerifyEndpoint); endpoint != "" {
		if verifyErr := VerifyTLS(endpoint, opts.VerifyServerName); verifyErr != nil {
			return strings.Join(logLines, "\n"), verifyErr
		}
		logLines = append(logLines, "macOS keychain TLS verification succeeded")
	}

	logLines = append(logLines, fmt.Sprintf("thumbprint=%s", thumbprint))
	logLines = append(logLines, fmt.Sprintf("commonName=%s", commonName))

	if opts.Metadata != nil {
		opts.Metadata.KeychainPath = keychainPath
		opts.Metadata.CertCommonName = commonName
		opts.Metadata.Thumbprint = thumbprint
		opts.Metadata.Alias = installer.DefaultAlias(opts.AssignmentID, opts.Alias)
	}

	return strings.Join(logLines, "\n"), nil
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	return removeFromKeychain(opts.Record, defaultExecutor{})
}

func removeFromKeychain(record installer.InstallRecord, exec installer.CommandExecutor) (string, error) {
	commonName := strings.TrimSpace(record.CertCommonName)
	if commonName == "" {
		return "", fmt.Errorf("missing certificate common name in install record")
	}

	keychainPath, err := ResolveKeychainPath(record.KeychainPath)
	if err != nil {
		return "", err
	}

	output, runErr := runSecurity(
		exec,
		"delete-certificate",
		"-c",
		commonName,
		keychainPath,
	)
	logLines := []string{
		fmt.Sprintf("security delete-certificate -c %q %s", commonName, keychainPath),
		strings.TrimSpace(string(output)),
	}
	if runErr != nil {
		if mapped := mapSecurityError(output, runErr, "", ""); mapped != nil {
			return strings.Join(logLines, "\n"), mapped
		}
		return strings.Join(logLines, "\n"), fmt.Errorf("%w: %s", runErr, strings.TrimSpace(string(output)))
	}

	return strings.Join(logLines, "\n"), nil
}

func ensurePlatform(opts installer.InstallOptions) error {
	if opts.Executor != nil {
		return nil
	}
	if runtime.GOOS != "darwin" {
		return installer.NewCodedError(
			"ERR_PLATFORM_MISMATCH",
			"macOS keychain installers require a macOS agent host",
		)
	}
	return nil
}

func commonNameFromPEM(chainPem string) (string, error) {
	trimmed := strings.TrimSpace(chainPem)
	if trimmed == "" {
		return "", fmt.Errorf("certificate chain is empty")
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
			return "", fmt.Errorf("parse certificate: %w", err)
		}

		cn := strings.TrimSpace(cert.Subject.CommonName)
		if cn == "" {
			return "", fmt.Errorf("certificate common name is empty")
		}
		return cn, nil
	}

	return "", fmt.Errorf("no certificate block found")
}

func mapSecurityError(output []byte, err error, installedThumbprint, optsThumbprint string) error {
	if err == nil {
		return nil
	}

	if isDuplicateCertError(output, err) {
		if optsThumbprint != "" && installedThumbprint == strings.TrimSpace(optsThumbprint) {
			return installer.NewCodedError("ERR_IDEMPOTENT", "certificate already trusted")
		}
	}

	combined := strings.ToLower(string(output) + " " + err.Error())
	switch {
	case strings.Contains(combined, "user interaction is not allowed"),
		strings.Contains(combined, "authorization"),
		strings.Contains(combined, "permission denied"),
		strings.Contains(combined, "not permitted"),
		strings.Contains(combined, "errsec"),
		strings.Contains(combined, "access denied"):
		return installer.NewCodedError(
			"ERR_PERMISSION",
			"Insufficient privileges to modify the macOS System keychain. Run the Capture Agent as root via launchd per the operations guide.",
		)
	}

	return nil
}

func isDuplicateCertError(output []byte, err error) bool {
	combined := strings.ToLower(string(output) + " " + err.Error())
	return strings.Contains(combined, "already exists") ||
		strings.Contains(combined, "duplicate")
}

func writeTempFile(prefix, content string) (path string, cleanup func(), err error) {
	file, err := os.CreateTemp("", prefix+"-*.pem")
	if err != nil {
		return "", nil, fmt.Errorf("create temp file: %w", err)
	}

	path = file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err := file.WriteString(strings.TrimSpace(content) + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("write temp file: %w", err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("close temp file: %w", err)
	}

	return path, func() { _ = os.Remove(path) }, nil
}
