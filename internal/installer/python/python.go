package python

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

// Installer implements python_certifi_bundle for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "python_certifi_bundle"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	if _, err := installer.ThumbprintFromPEM(opts.ChainPem); err != nil {
		return "", installer.NewCodedError("ERR_INVALID_PEM", "malformed certificate PEM")
	}

	bundlePath, err := ResolveBundlePath(opts.TrustStorePath, opts.PythonVenvPath)
	if err != nil {
		return "", err
	}

	alias := installer.DefaultAlias(opts.AssignmentID, opts.Alias)
	markerStart := fmt.Sprintf("# compliwise-%s-start", alias)
	markerEnd := fmt.Sprintf("# compliwise-%s-end", alias)
	thumbprintMarker := fmt.Sprintf("# compliwise-thumbprint:%s", strings.TrimSpace(opts.Thumbprint))

	existing, readErr := os.ReadFile(bundlePath)
	if readErr == nil {
		content := string(existing)
		if strings.Contains(content, thumbprintMarker) {
			return "idempotent: thumbprint unchanged in " + bundlePath, nil
		}
	}

	block := strings.Join([]string{
		markerStart,
		thumbprintMarker,
		strings.TrimSpace(opts.ChainPem),
		markerEnd,
		"",
	}, "\n")

	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	file, err := os.OpenFile(bundlePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", fmt.Errorf("open bundle file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString("\n" + block); err != nil {
		return "", fmt.Errorf("append bundle: %w", err)
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("appended cert block to %s", bundlePath))

	if envPath := strings.TrimSpace(opts.EnvFilePath); envPath != "" {
		if err := upsertEnvExport(envPath, requestsCAEnvKey, bundlePath); err != nil {
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
		if err := VerifyHTTPS(endpoint); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, "python HTTPS verification succeeded")
	}

	if opts.Metadata != nil {
		*opts.Metadata = installer.InstallRecord{
			CertPath:    bundlePath,
			EnvFilePath: strings.TrimSpace(opts.EnvFilePath),
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

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "bundle already absent: " + bundlePath, nil
		}
		return "", fmt.Errorf("read bundle file: %w", err)
	}

	alias := installer.DefaultAlias(record.AssignmentID, record.Alias)
	markerStart := fmt.Sprintf("# compliwise-%s-start", alias)
	markerEnd := fmt.Sprintf("# compliwise-%s-end", alias)

	content := string(data)
	start := strings.Index(content, markerStart)
	if start < 0 {
		return "marker block not found; nothing to remove", nil
	}
	end := strings.Index(content[start:], markerEnd)
	if end < 0 {
		return "", fmt.Errorf("marker end not found in bundle")
	}
	end = start + end + len(markerEnd)

	updated := content[:start] + content[end:]
	if err := os.WriteFile(bundlePath, []byte(strings.TrimRight(updated, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write bundle file: %w", err)
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("removed cert block from %s", bundlePath))

	if envPath := strings.TrimSpace(record.EnvFilePath); envPath != "" {
		if err := removeEnvExport(envPath, requestsCAEnvKey); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, fmt.Sprintf("cleared %s from %s", requestsCAEnvKey, envPath))
	}

	return strings.Join(logLines, "\n"), nil
}

func runReloadCommand(command []string) (string, error) {
	if len(command) == 0 {
		return "", nil
	}
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
