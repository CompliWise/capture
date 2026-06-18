package java

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveCacertsPath returns the first existing cacerts file under a JDK home.
func ResolveCacertsPath(javaHome string) string {
	home := strings.TrimSpace(javaHome)
	if home == "" {
		return ""
	}

	candidates := []string{
		filepath.Join(home, "lib", "security", "cacerts"),
		filepath.Join(home, "jre", "lib", "security", "cacerts"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// ResolveKeystorePath picks the target keystore file for JVM installers.
func ResolveKeystorePath(trustStoreType, trustStorePath, javaHome string) (string, error) {
	trimmedPath := strings.TrimSpace(trustStorePath)
	switch trustStoreType {
	case "java_pkcs12":
		if trimmedPath == "" {
			return "", fmt.Errorf("trustStorePath is required for java_pkcs12")
		}
		return trimmedPath, nil
	case "java_cacerts":
		if trimmedPath != "" {
			return trimmedPath, nil
		}
		if path := ResolveCacertsPath(javaHome); path != "" {
			return path, nil
		}
		if path := ResolveCacertsPath(os.Getenv("JAVA_HOME")); path != "" {
			return path, nil
		}
		return "", fmt.Errorf("trustStorePath or javaHome is required for java_cacerts")
	default:
		return "", fmt.Errorf("unsupported JVM trust store type %q", trustStoreType)
	}
}
