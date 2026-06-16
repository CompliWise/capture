package java

import (
	"os/exec"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

// KeytoolAlias returns the stable keytool alias for an assignment.
func KeytoolAlias(assignmentID, configuredAlias string) string {
	trimmed := strings.TrimSpace(configuredAlias)
	if trimmed == "" {
		trimmed = strings.TrimSpace(assignmentID)
	}
	if trimmed == "" {
		return "compliwise-cert"
	}
	safe := installer.SanitizeFileName(trimmed)
	if strings.HasPrefix(safe, "compliwise-") {
		return safe
	}
	return "compliwise-" + safe
}

// ImportCertArgs builds argv for keytool -importcert.
func ImportCertArgs(keytool, alias, pemPath, keystore, password string) []string {
	return []string{
		keytool,
		"-importcert",
		"-noprompt",
		"-alias", alias,
		"-file", pemPath,
		"-keystore", keystore,
		"-storepass", password,
	}
}

// DeleteAliasArgs builds argv for keytool -delete.
func DeleteAliasArgs(keytool, alias, keystore, password string) []string {
	return []string{
		keytool,
		"-delete",
		"-alias", alias,
		"-keystore", keystore,
		"-storepass", password,
	}
}

// ListAliasArgs builds argv for keytool -list on a single alias.
func ListAliasArgs(keytool, alias, keystore, password string) []string {
	return []string{
		keytool,
		"-list",
		"-alias", alias,
		"-keystore", keystore,
		"-storepass", password,
	}
}

func runKeytoolArgs(args []string) (string, error) {
	if len(args) == 0 {
		return "", exec.ErrNotFound
	}
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
