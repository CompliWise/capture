package windows

import (
	"regexp"
)

var (
	privateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----`)
	bearerTokenPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`)
)

// SanitizeInstallerLog redacts private key material and bearer tokens from installer output.
func SanitizeInstallerLog(log string) string {
	if log == "" {
		return log
	}
	sanitized := privateKeyPattern.ReplaceAllString(log, "[private key redacted]")
	sanitized = bearerTokenPattern.ReplaceAllString(sanitized, "Bearer [redacted]")
	return sanitized
}
