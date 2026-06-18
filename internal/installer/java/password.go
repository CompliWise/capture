package java

import (
	"fmt"
	"os"
	"strings"
)

// ResolveStorePasswordRef resolves env:VAR or file:/path password references.
func ResolveStorePasswordRef(ref string) (string, error) {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return "", nil
	}

	if strings.HasPrefix(trimmed, "env:") {
		name := strings.TrimSpace(strings.TrimPrefix(trimmed, "env:"))
		if name == "" {
			return "", fmt.Errorf("storePasswordRef env name is empty")
		}
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return value, nil
	}

	if strings.HasPrefix(trimmed, "file:") {
		path := strings.TrimSpace(strings.TrimPrefix(trimmed, "file:"))
		if path == "" {
			return "", fmt.Errorf("storePasswordRef file path is empty")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read store password file: %w", err)
		}
		value := strings.TrimSpace(string(data))
		if value == "" {
			return "", fmt.Errorf("store password file is empty")
		}
		return value, nil
	}

	return trimmed, nil
}

// ResolveStorePassword applies ref, direct password, env fallback, then JDK default.
func ResolveStorePassword(ref, directPassword, fallbackEnv string) string {
	if pwd, err := ResolveStorePasswordRef(ref); err == nil && pwd != "" {
		return pwd
	}
	if trimmed := strings.TrimSpace(directPassword); trimmed != "" {
		return trimmed
	}
	if value := strings.TrimSpace(os.Getenv(fallbackEnv)); value != "" {
		return value
	}
	return "changeit"
}
