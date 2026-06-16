package dotnet

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

const dotnetCAEnvKey = "DOTNET_SYSTEM_NET_HTTP_SOCKETSHTTPHANDLER_DLLIMPORTEXPORT_CUSTOMCAFILE"

// ResolveBundlePath returns the absolute PEM bundle file path for dotnet_root_store.
func ResolveBundlePath(configured string) (string, error) {
	trimmed := strings.TrimSpace(configured)
	if trimmed == "" {
		return "", fmt.Errorf("trust store path is required")
	}

	if strings.Contains(trimmed, "..") {
		return "", fmt.Errorf("path traversal is not allowed")
	}

	clean := filepath.Clean(trimmed)

	parent := filepath.Dir(clean)
	if err := installer.ValidatePathWithinBase(parent, clean); err != nil {
		return "", err
	}

	return clean, nil
}
