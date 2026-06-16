package macos

import (
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

const DefaultSystemKeychain = "/Library/Keychains/System.keychain"

// ResolveKeychainPath returns the absolute keychain path for macos_keychain_system.
func ResolveKeychainPath(configured string) (string, error) {
	trimmed := strings.TrimSpace(configured)
	if trimmed == "" {
		return DefaultSystemKeychain, nil
	}

	cleaned := filepath.Clean(trimmed)
	if strings.Contains(cleaned, "..") {
		return "", installer.NewCodedError(
			"ERR_INVALID_PATH",
			"keychain path traversal is not allowed",
		)
	}

	if !isAllowedKeychainPath(cleaned) {
		return "", installer.NewCodedError(
			"ERR_INVALID_PATH",
			"keychain path must be under /Library/Keychains or a user Library/Keychains directory",
		)
	}

	return cleaned, nil
}

func isAllowedKeychainPath(path string) bool {
	if strings.HasPrefix(path, "/Library/Keychains/") {
		return true
	}

	normalized := filepath.ToSlash(path)
	if strings.Contains(normalized, "/Library/Keychains/") {
		return strings.HasSuffix(normalized, ".keychain") ||
			strings.HasSuffix(normalized, ".keychain-db")
	}

	return false
}
