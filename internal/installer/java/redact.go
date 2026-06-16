package java

import (
	"regexp"
	"strings"
)

var (
	storePassPattern = regexp.MustCompile(`(?i)-storepass\s+\S+`)
	envRefPattern    = regexp.MustCompile(`(?i)env:[A-Z_][A-Z0-9_]*`)
)

// SanitizeInstallerLog redacts keystore passwords and private key PEM from installer output.
func SanitizeInstallerLog(log string) string {
	if strings.TrimSpace(log) == "" {
		return log
	}

	sanitized := storePassPattern.ReplaceAllString(log, "-storepass [REDACTED]")
	sanitized = envRefPattern.ReplaceAllString(sanitized, "env:[REDACTED]")
	sanitized = redactPrivateKeyBlocks(sanitized)
	return sanitized
}

func redactPrivateKeyBlocks(log string) string {
	markers := []struct {
		begin string
		end   string
	}{
		{"-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"},
		{"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"},
		{"-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"},
	}

	result := log
	for _, marker := range markers {
		for {
			start := strings.Index(result, marker.begin)
			if start < 0 {
				break
			}
			end := strings.Index(result[start:], marker.end)
			if end < 0 {
				break
			}
			end += start + len(marker.end)
			result = result[:start] + "[PRIVATE KEY REDACTED]" + result[end:]
		}
	}
	return result
}
