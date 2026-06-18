package java

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

// Installer implements java_cacerts and java_pkcs12 trust store installers.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	switch trustStoreType {
	case "java_cacerts":
		return materialType == "trust_anchor"
	case "java_pkcs12":
		return materialType == "trust_anchor" || materialType == "server_identity"
	default:
		return false
	}
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	keystore, err := ResolveKeystorePath(
		opts.TrustStoreType,
		opts.TrustStorePath,
		opts.JavaHome,
	)
	if err != nil {
		return "", err
	}

	fallbackEnv := "JAVA_CACERTS_PASSWORD"
	if opts.TrustStoreType == "java_pkcs12" {
		fallbackEnv = "PKCS12_PASSWORD"
	}
	password := ResolveStorePassword(opts.StorePasswordRef, opts.StorePassword, fallbackEnv)
	alias := KeytoolAlias(opts.AssignmentID, opts.Alias)

	if opts.MaterialType == "server_identity" {
		return i.installServerIdentity(opts, keystore, alias, password)
	}

	return i.installTrustAnchor(opts, keystore, alias, password)
}

func (i *Installer) installServerIdentity(
	opts installer.InstallOptions,
	keystore, alias, password string,
) (string, error) {
	if strings.TrimSpace(opts.PrivateKeyPem) == "" {
		return "", fmt.Errorf("private key is required for server_identity")
	}
	if err := installer.ValidateKeyMatchesCert(opts.ChainPem, opts.PrivateKeyPem); err != nil {
		return "", err
	}

	output, err := ExportPKCS12FromPEM(
		opts.ChainPem,
		opts.PrivateKeyPem,
		keystore,
		alias,
		password,
	)
	logLines := []string{SanitizeInstallerLog(strings.TrimSpace(output))}
	if err != nil {
		return strings.Join(logLines, "\n"), err
	}
	logLines = append(logLines, fmt.Sprintf("wrote PKCS#12 identity to %s", keystore))

	if reloadLog, reloadErr := runReloadCommand(opts.ReloadCommand); reloadErr != nil {
		logLines = append(logLines, reloadLog)
		return SanitizeInstallerLog(strings.Join(logLines, "\n")), installer.NewCodedError(
			"ERR_RELOAD_FAILED",
			fmt.Sprintf("reload command failed: %v", reloadErr),
		)
	} else if reloadLog != "" {
		logLines = append(logLines, reloadLog)
	}

	if strings.TrimSpace(opts.VerifyEndpoint) != "" {
		if err := verifyAfterInstall(keystore, alias, password); err != nil {
			logLines = append(logLines, err.Error())
			return SanitizeInstallerLog(strings.Join(logLines, "\n")), err
		}
	}

	return SanitizeInstallerLog(strings.Join(logLines, "\n")), nil
}

func (i *Installer) installTrustAnchor(
	opts installer.InstallOptions,
	keystore, alias, password string,
) (string, error) {
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		return "", fmt.Errorf("keytool not found on PATH")
	}

	if existingThumbprint, listErr := listAliasThumbprint(keytool, alias, keystore, password); listErr == nil {
		if existingThumbprint != "" &&
			existingThumbprint == normalizeKeytoolFingerprint(opts.Thumbprint) &&
			opts.Thumbprint != "" {
			return SanitizeInstallerLog(
				fmt.Sprintf("idempotent: thumbprint unchanged for alias %s", alias),
			), nil
		}
	}

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
	if deleteOutput, deleteErr := runKeytoolArgs(
		DeleteAliasArgs(keytool, alias, keystore, password),
	); deleteErr == nil {
		if trimmed := strings.TrimSpace(deleteOutput); trimmed != "" {
			logLines = append(logLines, trimmed)
		}
	}

	importOutput, importErr := runKeytoolArgs(
		ImportCertArgs(keytool, alias, tmpPath, keystore, password),
	)
	logLines = append(logLines, strings.TrimSpace(importOutput))
	if importErr != nil {
		return SanitizeInstallerLog(strings.Join(logLines, "\n")), fmt.Errorf(
			"keytool importcert: %w",
			importErr,
		)
	}
	logLines = append(logLines, "keytool importcert: done")

	if reloadLog, reloadErr := runReloadCommand(opts.ReloadCommand); reloadErr != nil {
		logLines = append(logLines, reloadLog)
		return SanitizeInstallerLog(strings.Join(logLines, "\n")), installer.NewCodedError(
			"ERR_RELOAD_FAILED",
			fmt.Sprintf("reload command failed: %v", reloadErr),
		)
	} else if reloadLog != "" {
		logLines = append(logLines, reloadLog)
	}

	if strings.TrimSpace(opts.VerifyEndpoint) != "" {
		if err := verifyAfterInstall(keystore, alias, password); err != nil {
			logLines = append(logLines, err.Error())
			return SanitizeInstallerLog(strings.Join(logLines, "\n")), err
		}
	}

	return SanitizeInstallerLog(strings.Join(logLines, "\n")), nil
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	keystore := strings.TrimSpace(record.TrustStorePath)
	if keystore == "" {
		return "", fmt.Errorf("missing keystore path in install record")
	}

	if opts.TrustStoreType == "java_pkcs12" && strings.TrimSpace(record.KeyPath) != "" {
		if err := os.Remove(keystore); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("remove pkcs12 file: %w", err)
		}
		return SanitizeInstallerLog(fmt.Sprintf("removed PKCS#12 file %s", keystore)), nil
	}

	keytool, err := exec.LookPath("keytool")
	if err != nil {
		return "", fmt.Errorf("keytool not found on PATH")
	}

	alias := strings.TrimSpace(record.Alias)
	if alias == "" {
		alias = KeytoolAlias(record.AssignmentID, "")
	}
	password := ResolveStorePassword("", "", "JAVA_CACERTS_PASSWORD")

	output, err := runKeytoolArgs(DeleteAliasArgs(keytool, alias, keystore, password))
	if err != nil {
		return SanitizeInstallerLog(strings.TrimSpace(output)), err
	}

	return SanitizeInstallerLog("keytool delete: done\n" + strings.TrimSpace(output)), nil
}

// RecordPaths returns install metadata for state persistence.
func RecordPaths(opts installer.InstallOptions) (certPath string, trustStorePath string) {
	keystore, err := ResolveKeystorePath(
		opts.TrustStoreType,
		opts.TrustStorePath,
		opts.JavaHome,
	)
	if err != nil {
		keystore = strings.TrimSpace(opts.TrustStorePath)
	}
	alias := KeytoolAlias(opts.AssignmentID, opts.Alias)
	if opts.MaterialType == "server_identity" {
		return keystore, keystore
	}
	return keystore + "#" + alias, keystore
}

func verifyAfterInstall(keystore, alias, password string) error {
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		return installer.NewCodedError("ERR_VERIFY_FAILED", "keytool not found for verification")
	}
	return VerifyKeystoreAlias(keytool, alias, keystore, password)
}

func runReloadCommand(command []string) (string, error) {
	if len(command) == 0 {
		return "", nil
	}
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
