package java

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExportPKCS12FromPEM writes a PKCS#12 keystore from PEM cert and key material.
func ExportPKCS12FromPEM(certPem, keyPem, destPath, alias, password string) (string, error) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		return "", fmt.Errorf("openssl not found on PATH")
	}

	certFile, err := os.CreateTemp("", "compliwise-cert-*.pem")
	if err != nil {
		return "", fmt.Errorf("create temp cert: %w", err)
	}
	certPath := certFile.Name()
	defer os.Remove(certPath)

	if _, err := certFile.WriteString(strings.TrimSpace(certPem) + "\n"); err != nil {
		_ = certFile.Close()
		return "", fmt.Errorf("write temp cert: %w", err)
	}
	if err := certFile.Close(); err != nil {
		return "", fmt.Errorf("close temp cert: %w", err)
	}

	keyFile, err := os.CreateTemp("", "compliwise-key-*.pem")
	if err != nil {
		return "", fmt.Errorf("create temp key: %w", err)
	}
	keyPath := keyFile.Name()
	defer os.Remove(keyPath)

	if _, err := keyFile.WriteString(strings.TrimSpace(keyPem) + "\n"); err != nil {
		_ = keyFile.Close()
		return "", fmt.Errorf("write temp key: %w", err)
	}
	if err := keyFile.Close(); err != nil {
		return "", fmt.Errorf("close temp key: %w", err)
	}

	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("create pkcs12 directory: %w", err)
	}

	tmpDest := destPath + ".tmp"
	cmd := exec.Command(
		openssl,
		"pkcs12",
		"-export",
		"-in", certPath,
		"-inkey", keyPath,
		"-out", tmpDest,
		"-name", alias,
		"-password", "pass:"+password,
		"-noiter",
		"-nomaciter",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.Remove(tmpDest)
		return SanitizeInstallerLog(string(output)), fmt.Errorf("openssl pkcs12 export: %w", err)
	}

	if err := os.Rename(tmpDest, destPath); err != nil {
		_ = os.Remove(tmpDest)
		return SanitizeInstallerLog(string(output)), fmt.Errorf("finalize pkcs12 file: %w", err)
	}

	return SanitizeInstallerLog(string(output)), nil
}
