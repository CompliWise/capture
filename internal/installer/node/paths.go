package node

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

const DefaultTrustStorePath = "/etc/compliwise/ca-bundles"

// ResolveTrustStorePath returns the PEM drop directory for node_extra_ca_certs.
func ResolveTrustStorePath(configured string) string {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed
	}
	return DefaultTrustStorePath
}

// BundlePath resolves the absolute PEM bundle path for an assignment.
func BundlePath(basePath, assignmentID, alias string) (string, error) {
	base := ResolveTrustStorePath(basePath)
	if err := installer.ValidatePathWithinBase(base, base); err != nil {
		return "", err
	}

	key := installer.SanitizeFileName(installer.DefaultAlias(assignmentID, alias))
	bundle := filepath.Join(base, fmt.Sprintf("compliwise-%s.pem", key))
	if err := installer.ValidatePathWithinBase(base, bundle); err != nil {
		return "", err
	}
	return bundle, nil
}
