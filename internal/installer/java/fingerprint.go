package java

import (
	"fmt"
	"regexp"
	"strings"
)

var keytoolSHA256Pattern = regexp.MustCompile(`(?i)SHA256:\s*([0-9A-Fa-f:]+)`)

func parseAliasThumbprintFromList(output string) string {
	match := keytoolSHA256Pattern.FindStringSubmatch(output)
	if match == nil {
		return ""
	}
	return normalizeKeytoolFingerprint(match[1])
}

func normalizeKeytoolFingerprint(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
}

func listAliasThumbprint(keytool, alias, keystore, password string) (string, error) {
	args := []string{
		keytool,
		"-list",
		"-v",
		"-alias", alias,
		"-keystore", keystore,
		"-storepass", password,
	}
	output, err := runKeytoolArgs(args)
	if err != nil {
		return "", err
	}
	thumbprint := parseAliasThumbprintFromList(output)
	if thumbprint == "" {
		return "", fmt.Errorf("alias thumbprint not found")
	}
	return thumbprint, nil
}
