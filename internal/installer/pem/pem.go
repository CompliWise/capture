package pem

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

// Installer implements pem_directory for trust anchors and server identity.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	if trustStoreType != "pem_directory" {
		return false
	}
	return materialType == "trust_anchor" || materialType == "server_identity"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	switch opts.MaterialType {
	case "server_identity":
		return i.installServerIdentity(opts)
	default:
		return i.installTrustAnchor(opts)
	}
}

func (i *Installer) installTrustAnchor(opts installer.InstallOptions) (string, error) {
	storePath := strings.TrimSpace(opts.TrustStorePath)
	if storePath == "" {
		return "", fmt.Errorf("trustStorePath is required for pem_directory")
	}

	destPath := filepath.Join(storePath, certFileName(opts.CertFileName))

	if err := installer.ValidatePathWithinBase(storePath, destPath); err != nil {
		return "", err
	}

	if existingThumbprint, err := fileThumbprint(destPath); err == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + destPath, nil
	}

	if err := os.MkdirAll(storePath, 0o755); err != nil {
		return "", fmt.Errorf("create pem directory: %w", err)
	}

	if err := installer.AtomicWriteFile(destPath, opts.ChainPem, 0o644); err != nil {
		return "", err
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", destPath))

	if len(opts.ReloadCommand) > 0 {
		reloadOutput, reloadErr := runReloadCommand(opts.ReloadCommand)
		logLines = append(
			logLines,
			fmt.Sprintf("%s %s", strings.Join(opts.ReloadCommand, " "), strings.TrimSpace(reloadOutput)),
		)
		if reloadErr != nil {
			return strings.Join(logLines, "\n"), reloadErr
		}
	}

	return strings.Join(logLines, "\n"), nil
}

func (i *Installer) installServerIdentity(opts installer.InstallOptions) (string, error) {
	storePath := strings.TrimSpace(opts.TrustStorePath)
	if storePath == "" {
		return "", fmt.Errorf("trustStorePath is required for pem_directory")
	}
	if strings.TrimSpace(opts.PrivateKeyPem) == "" {
		return "", fmt.Errorf("private key is required for server_identity")
	}

	if err := installer.ValidateKeyMatchesCert(opts.ChainPem, opts.PrivateKeyPem); err != nil {
		return "", err
	}

	certPath := filepath.Join(storePath, certFileName(opts.CertFileName))
	keyPath := filepath.Join(storePath, keyFileName(opts.KeyFileName))

	if err := installer.ValidatePathWithinBase(storePath, certPath); err != nil {
		return "", err
	}
	if err := installer.ValidatePathWithinBase(storePath, keyPath); err != nil {
		return "", err
	}

	if existingThumbprint, err := fileThumbprint(certPath); err == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		if _, statErr := os.Stat(keyPath); statErr == nil {
			return fmt.Sprintf(
				"idempotent: thumbprint unchanged at %s with key at %s",
				certPath,
				keyPath,
			), nil
		}
	}

	if err := os.MkdirAll(storePath, 0o755); err != nil {
		return "", fmt.Errorf("create pem directory: %w", err)
	}

	if err := installer.AtomicWriteFile(certPath, opts.ChainPem, 0o644); err != nil {
		return "", err
	}

	keyMode := installer.ParseFileMode(opts.KeyPermissionMode, 0o600)
	keyContent := strings.TrimSpace(opts.PrivateKeyPem)
	if err := installer.AtomicWriteFile(keyPath, keyContent, keyMode); err != nil {
		return "", err
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", certPath))
	logLines = append(logLines, fmt.Sprintf("wrote %s (mode %04o)", keyPath, keyMode&0o777))

	if len(opts.ReloadCommand) > 0 {
		reloadOutput, reloadErr := runReloadCommand(opts.ReloadCommand)
		logLines = append(
			logLines,
			fmt.Sprintf("%s %s", strings.Join(opts.ReloadCommand, " "), strings.TrimSpace(reloadOutput)),
		)
		if reloadErr != nil {
			return strings.Join(logLines, "\n"), installer.NewCodedError(
				"ERR_RELOAD_FAILED",
				fmt.Sprintf("reload command failed: %v", reloadErr),
			)
		}
	}

	return strings.Join(logLines, "\n"), nil
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	certPath := strings.TrimSpace(record.CertPath)
	if certPath == "" {
		return "", fmt.Errorf("missing cert path in install record")
	}

	var logLines []string

	if err := removeFile(certPath); err != nil {
		return "", err
	}
	logLines = append(logLines, fmt.Sprintf("removed %s", certPath))

	keyPath := strings.TrimSpace(record.KeyPath)
	if keyPath != "" {
		if err := removeFile(keyPath); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, fmt.Sprintf("removed %s", keyPath))
	}

	return strings.Join(logLines, "\n"), nil
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove file %s: %w", path, err)
	}
	return nil
}

func certFileName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "tls.crt"
	}
	return installer.SanitizeFileName(name)
}

func keyFileName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "tls.key"
	}
	return installer.SanitizeFileName(name)
}

func fileThumbprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return installer.ThumbprintFromPEM(string(data))
}

func runReloadCommand(command []string) (string, error) {
	if len(command) == 0 {
		return "", nil
	}
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
