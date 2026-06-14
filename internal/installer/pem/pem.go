package pem

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

// Installer implements pem_directory for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "pem_directory"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	storePath := strings.TrimSpace(opts.TrustStorePath)
	if storePath == "" {
		return "", fmt.Errorf("trustStorePath is required for pem_directory")
	}

	fileName := installer.SanitizeFileName(opts.CertFileName)
	destPath := filepath.Join(storePath, fileName)

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

	tmpPath := destPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.TrimSpace(opts.ChainPem)+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write temp certificate file: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("rename certificate file: %w", err)
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

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	certPath := strings.TrimSpace(record.CertPath)
	if certPath == "" {
		return "", fmt.Errorf("missing cert path in install record")
	}

	if err := os.Remove(certPath); err != nil {
		if os.IsNotExist(err) {
			return "cert already absent: " + certPath, nil
		}
		return "", fmt.Errorf("remove certificate file: %w", err)
	}

	return fmt.Sprintf("removed %s", certPath), nil
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
