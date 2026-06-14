package java

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

// Installer implements java_cacerts for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "java_cacerts"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	keystore := strings.TrimSpace(opts.TrustStorePath)
	if keystore == "" {
		return "", fmt.Errorf("trustStorePath is required for java_cacerts")
	}

	keytool, err := exec.LookPath("keytool")
	if err != nil {
		return "", fmt.Errorf("keytool not found on PATH")
	}

	alias := installer.DefaultAlias(opts.AssignmentID, opts.Alias)
	password := resolveStorePassword(opts.StorePassword)

	tmp, err := os.CreateTemp("", "compliwise-cert-*.pem")
	if err != nil {
		return "", fmt.Errorf("create temp pem: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(strings.TrimSpace(opts.ChainPem) + "\n"); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write temp pem: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp pem: %w", err)
	}

	var logLines []string
	if deleteOutput, deleteErr := runKeytoolDelete(keytool, alias, keystore, password); deleteErr == nil {
		logLines = append(logLines, strings.TrimSpace(deleteOutput))
	}

	importCmd := exec.Command(
		keytool,
		"-importcert",
		"-noprompt",
		"-alias", alias,
		"-file", tmpPath,
		"-keystore", keystore,
		"-storepass", password,
	)
	output, err := importCmd.CombinedOutput()
	logLines = append(logLines, strings.TrimSpace(string(output)))
	if err != nil {
		return strings.Join(logLines, "\n"), fmt.Errorf("keytool importcert: %w", err)
	}

	return "keytool importcert: done\n" + strings.Join(logLines, "\n"), nil
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	keystore := strings.TrimSpace(record.TrustStorePath)
	if keystore == "" {
		return "", fmt.Errorf("missing keystore path in install record")
	}

	keytool, err := exec.LookPath("keytool")
	if err != nil {
		return "", fmt.Errorf("keytool not found on PATH")
	}

	alias := installer.DefaultAlias(record.AssignmentID, record.Alias)
	password := resolveStorePassword("")

	output, err := runKeytoolDelete(keytool, alias, keystore, password)
	if err != nil {
		return strings.TrimSpace(output), err
	}

	return "keytool delete: done\n" + strings.TrimSpace(output), nil
}

func runKeytoolDelete(keytool, alias, keystore, password string) (string, error) {
	cmd := exec.Command(
		keytool,
		"-delete",
		"-alias", alias,
		"-keystore", keystore,
		"-storepass", password,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func resolveStorePassword(configured string) string {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed
	}
	if value := strings.TrimSpace(os.Getenv("JAVA_CACERTS_PASSWORD")); value != "" {
		return value
	}
	return "changeit"
}

// RecordPaths returns install metadata for state persistence.
func RecordPaths(opts installer.InstallOptions) (certPath string, trustStorePath string) {
	return filepath.Join(strings.TrimSpace(opts.TrustStorePath), installer.DefaultAlias(opts.AssignmentID, opts.Alias)),
		strings.TrimSpace(opts.TrustStorePath)
}
