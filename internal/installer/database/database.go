package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/linux"
)

var verifyRunner = defaultVerifyRunner

func defaultVerifyRunner(endpoint, bundlePath, serverName string) error {
	return linux.VerifyTLS(endpoint, bundlePath, serverName)
}

// Installer implements database TLS trust store types for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	if materialType != "trust_anchor" {
		return false
	}
	switch trustStoreType {
	case "postgresql_ssl_root", "mysql_ssl_ca", "oracle_wallet":
		return true
	default:
		return false
	}
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	if _, err := installer.ThumbprintFromPEM(opts.ChainPem); err != nil {
		return "", installer.NewCodedError("ERR_INVALID_PEM", "malformed certificate PEM")
	}

	switch opts.TrustStoreType {
	case "postgresql_ssl_root":
		return installPostgreSQL(opts)
	case "mysql_ssl_ca":
		return installMySQL(opts)
	case "oracle_wallet":
		return installOracle(opts)
	default:
		return "", fmt.Errorf("unsupported database trust store type %q", opts.TrustStoreType)
	}
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	switch opts.TrustStoreType {
	case "postgresql_ssl_root", "mysql_ssl_ca":
		return removeCertFile(opts.Record)
	case "oracle_wallet":
		return removeOracle(opts)
	default:
		return "", fmt.Errorf("unsupported database trust store type %q", opts.TrustStoreType)
	}
}

func installPostgreSQL(opts installer.InstallOptions) (string, error) {
	targetPath, err := ResolveTargetPath(
		opts.TrustStoreType,
		opts.TrustStorePath,
		opts.CertFileName,
		opts.DBUser,
	)
	if err != nil {
		return "", err
	}

	if existingThumbprint, readErr := fileThumbprint(targetPath); readErr == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + targetPath, nil
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", fmt.Errorf("create postgresql cert directory: %w", err)
	}

	if err := installer.AtomicWriteFile(targetPath, opts.ChainPem, 0o600); err != nil {
		return "", err
	}

	if err := applyPostgresOwnership(targetPath, opts.DBUser); err != nil {
		return "", err
	}

	return finishInstall(opts, targetPath, targetPath)
}

func installMySQL(opts installer.InstallOptions) (string, error) {
	targetPath, err := ResolveTargetPath(
		opts.TrustStoreType,
		opts.TrustStorePath,
		opts.CertFileName,
		opts.DBUser,
	)
	if err != nil {
		return "", err
	}

	if existingThumbprint, readErr := fileThumbprint(targetPath); readErr == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + targetPath, nil
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", fmt.Errorf("create mysql cert directory: %w", err)
	}

	if err := installer.AtomicWriteFile(targetPath, opts.ChainPem, 0o644); err != nil {
		return "", err
	}

	return finishInstall(opts, targetPath, targetPath)
}

func installOracle(opts installer.InstallOptions) (string, error) {
	walletDir, err := ResolveTargetPath(
		opts.TrustStoreType,
		opts.TrustStorePath,
		opts.CertFileName,
		opts.DBUser,
	)
	if err != nil {
		return "", err
	}

	certPath := OracleTrustedCertPath(walletDir)
	exec := resolveExecutor(opts)

	if err := os.MkdirAll(walletDir, 0o700); err != nil {
		return "", fmt.Errorf("create oracle wallet directory: %w", err)
	}

	if err := installer.AtomicWriteFile(certPath, opts.ChainPem, 0o600); err != nil {
		return "", err
	}

	output, orapkiErr := runOrapki(
		exec,
		"wallet", "add",
		"-wallet", walletDir,
		"-trusted_cert",
		"-cert", certPath,
	)
	if orapkiErr != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = orapkiErr.Error()
		}
		return message, fmt.Errorf("orapki wallet add failed: %s", message)
	}

	logLines := make([]string, 0, 1)
	logLines = append(logLines, fmt.Sprintf("orapki wallet add %s", walletDir))

	if opts.Metadata != nil {
		opts.Metadata.CertPath = certPath
		opts.Metadata.TrustStorePath = walletDir
		opts.Metadata.Thumbprint = strings.TrimSpace(opts.Thumbprint)
	}

	return strings.Join(logLines, "\n"), nil
}

func finishInstall(opts installer.InstallOptions, certPath, trustStorePath string) (string, error) {
	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", certPath))
	if opts.Thumbprint != "" {
		logLines = append(logLines, fmt.Sprintf("thumbprint=%s", strings.TrimSpace(opts.Thumbprint)))
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
		if verifyErr := verifyRunner(endpoint, certPath, opts.VerifyServerName); verifyErr != nil {
			return strings.Join(logLines, "\n"), verifyErr
		}
		logLines = append(logLines, "database TLS verification succeeded")
	}

	if opts.Metadata != nil {
		opts.Metadata.CertPath = certPath
		opts.Metadata.TrustStorePath = trustStorePath
		opts.Metadata.Thumbprint = strings.TrimSpace(opts.Thumbprint)
	}

	return strings.Join(logLines, "\n"), nil
}

func removeCertFile(record installer.InstallRecord) (string, error) {
	certPath := strings.TrimSpace(record.CertPath)
	if certPath == "" {
		return "", fmt.Errorf("missing cert path in install record")
	}

	if err := os.Remove(certPath); err != nil {
		if os.IsNotExist(err) {
			return "cert file already absent: " + certPath, nil
		}
		return "", fmt.Errorf("remove cert file: %w", err)
	}

	return fmt.Sprintf("removed %s", certPath), nil
}

func removeOracle(opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	walletDir := strings.TrimSpace(record.TrustStorePath)
	certPath := strings.TrimSpace(record.CertPath)
	if walletDir == "" {
		return "", fmt.Errorf("missing wallet directory in install record")
	}
	if certPath == "" {
		certPath = OracleTrustedCertPath(walletDir)
	}

	exec := resolveExecutor(installer.InstallOptions{Executor: nil})
	output, err := runOrapki(
		exec,
		"wallet", "remove",
		"-wallet", walletDir,
		"-trusted_cert",
		"-cert", certPath,
	)
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return message, fmt.Errorf("orapki wallet remove failed: %s", message)
	}

	if removeErr := os.Remove(certPath); removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Sprintf("orapki wallet remove %s", walletDir), removeErr
	}

	return fmt.Sprintf("removed trusted cert from wallet %s", walletDir), nil
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
	executor := defaultExecutor{}
	output, err := executor.Run(command[0], command[1:]...)
	return string(output), err
}
