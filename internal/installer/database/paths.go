package database

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

// ExpandTrustStorePath expands a leading ~ using dbUser home or the current user.
func ExpandTrustStorePath(path, dbUser string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("trustStorePath is required")
	}

	if strings.Contains(trimmed, "..") {
		return "", fmt.Errorf("path traversal is not allowed")
	}

	if strings.HasPrefix(trimmed, "~/") || trimmed == "~" {
		home, err := resolveHomeDir(dbUser)
		if err != nil {
			return "", err
		}
		if trimmed == "~" {
			return filepath.Clean(home), nil
		}
		trimmed = filepath.Join(home, strings.TrimPrefix(trimmed, "~/"))
	}

	cleaned := filepath.Clean(trimmed)
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path traversal is not allowed")
	}

	return cleaned, nil
}

// ResolveTargetPath returns the absolute cert file path or Oracle wallet directory.
func ResolveTargetPath(trustStoreType, trustStorePath, certFileName, dbUser string) (string, error) {
	expanded, err := ExpandTrustStorePath(trustStorePath, dbUser)
	if err != nil {
		return "", err
	}

	switch trustStoreType {
	case "oracle_wallet":
		if isDirectoryPath(expanded) {
			return filepath.Clean(expanded), nil
		}
		return expanded, nil
	case "postgresql_ssl_root":
		return resolveCertFilePath(expanded, certFileName, "root.crt")
	case "mysql_ssl_ca":
		return resolveCertFilePath(expanded, certFileName, "ca.pem")
	default:
		return "", fmt.Errorf("unsupported database trust store type %q", trustStoreType)
	}
}

func resolveCertFilePath(expanded, certFileName, defaultName string) (string, error) {
	name := strings.TrimSpace(certFileName)
	if name == "" {
		name = defaultName
	} else {
		name = installer.SanitizeFileName(name)
	}

	if strings.HasSuffix(expanded, string(os.PathSeparator)) {
		return filepath.Join(expanded, name), nil
	}

	if info, err := os.Stat(expanded); err == nil && info.IsDir() {
		return filepath.Join(expanded, name), nil
	}

	ext := strings.ToLower(filepath.Ext(filepath.Base(expanded)))
	if ext == ".crt" || ext == ".pem" {
		return expanded, nil
	}

	return filepath.Join(expanded, name), nil
}

func isDirectoryPath(path string) bool {
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		return true
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func resolveHomeDir(dbUser string) (string, error) {
	username := strings.TrimSpace(dbUser)
	if username != "" {
		record, err := user.Lookup(username)
		if err != nil {
			return "", fmt.Errorf("resolve home for user %q: %w", username, err)
		}
		if strings.TrimSpace(record.HomeDir) == "" {
			return "", fmt.Errorf("home directory not found for user %q", username)
		}
		return record.HomeDir, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve current user home: %w", err)
	}
	return home, nil
}

// OracleTrustedCertPath returns the PEM path stored alongside an Oracle wallet.
func OracleTrustedCertPath(walletDir string) string {
	return filepath.Join(walletDir, "compliwise-trusted-ca.pem")
}
