package node

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

const envKey = "NODE_EXTRA_CA_CERTS"

// Installer implements node_extra_ca_certs for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "node_extra_ca_certs"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	basePath := strings.TrimSpace(opts.TrustStorePath)
	if basePath == "" {
		return "", fmt.Errorf("trustStorePath is required for node_extra_ca_certs")
	}

	if err := installer.ValidatePathWithinBase(basePath, basePath); err != nil {
		return "", err
	}

	bundlePath := filepath.Join(basePath, fmt.Sprintf("compliwise-%s.pem", opts.AssignmentID))

	if existingThumbprint, err := fileThumbprint(bundlePath); err == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + bundlePath, nil
	}

	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	if err := os.WriteFile(bundlePath, []byte(strings.TrimSpace(opts.ChainPem)+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write bundle file: %w", err)
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", bundlePath))

	if envPath := strings.TrimSpace(opts.EnvFilePath); envPath != "" {
		if err := upsertEnvLine(envPath, envKey, bundlePath); err != nil {
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
		if err := removeEnvLine(envPath, envKey); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, fmt.Sprintf("cleared %s from %s", envKey, envPath))
	}

	return strings.Join(logLines, "\n"), nil
}

func fileThumbprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return installer.ThumbprintFromPEM(string(data))
}

func upsertEnvLine(path, key, value string) error {
	lines := []string{}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				lines = append(lines, line)
				continue
			}
			entryKey, _, ok := strings.Cut(trimmed, "=")
			if ok && strings.TrimSpace(entryKey) == key {
				continue
			}
			lines = append(lines, line)
		}
	}

	lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create env directory: %w", err)
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func removeEnvLine(path, key string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		entryKey, _, ok := strings.Cut(trimmed, "=")
		if ok && strings.TrimSpace(entryKey) == key {
			continue
		}
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	if content == "" {
		return os.Remove(path)
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func runReloadCommand(command []string) (string, error) {
	if len(command) == 0 {
		return "", nil
	}
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
