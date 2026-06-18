package node

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

// Installer implements node_extra_ca_certs for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "node_extra_ca_certs"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	if _, err := installer.ThumbprintFromPEM(opts.ChainPem); err != nil {
		return "", installer.NewCodedError("ERR_INVALID_PEM", "malformed certificate PEM")
	}

	bundlePath, err := BundlePath(opts.TrustStorePath, opts.AssignmentID, opts.Alias)
	if err != nil {
		return "", err
	}

	if existingThumbprint, readErr := fileThumbprint(bundlePath); readErr == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + bundlePath, nil
	}

	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	if err := installer.AtomicWriteFile(bundlePath, opts.ChainPem, 0o644); err != nil {
		return "", err
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", bundlePath))
	logLines = appendOpensslCaLog(logLines, opts)

	if envPath := strings.TrimSpace(opts.EnvFilePath); envPath != "" {
		if err := upsertEnvLine(envPath, nodeExtraCAEnvKey, bundlePath); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, fmt.Sprintf("updated %s", envPath))
	}

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

	if endpoint := strings.TrimSpace(opts.VerifyEndpoint); endpoint != "" {
		if verifyErr := VerifyHTTPS(endpoint); verifyErr != nil {
			return strings.Join(logLines, "\n"), verifyErr
		}
		logLines = append(logLines, "node HTTPS verification succeeded")
	}

	if opts.Metadata != nil {
		opts.Metadata.CertPath = bundlePath
		opts.Metadata.TrustStorePath = ResolveTrustStorePath(opts.TrustStorePath)
		opts.Metadata.EnvFilePath = strings.TrimSpace(opts.EnvFilePath)
	}

	return strings.Join(logLines, "\n"), nil
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	bundlePath := strings.TrimSpace(record.CertPath)
	if bundlePath == "" {
		return "", fmt.Errorf("missing bundle path in install record")
	}

	var logLines []string
	if err := os.Remove(bundlePath); err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("remove bundle file: %w", err)
		}
		logLines = append(logLines, "bundle already absent")
	} else {
		logLines = append(logLines, fmt.Sprintf("removed %s", bundlePath))
	}

	if envPath := strings.TrimSpace(record.EnvFilePath); envPath != "" {
		if err := removeEnvLine(envPath, nodeExtraCAEnvKey); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, fmt.Sprintf("cleared %s from %s", nodeExtraCAEnvKey, envPath))
	}

	return strings.Join(logLines, "\n"), nil
}

func appendOpensslCaLog(lines []string, opts installer.InstallOptions) []string {
	if !shouldDocumentOpensslCA(opts) {
		return lines
	}
	return append(lines, "systemd: add ExecStart flag: node --use-openssl-ca")
}

func shouldDocumentOpensslCA(opts installer.InstallOptions) bool {
	if opts.UseOpensslCa {
		return true
	}
	for _, flag := range opts.NodeFlags {
		if strings.TrimSpace(flag) == "--use-openssl-ca" {
			return true
		}
	}
	return false
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
