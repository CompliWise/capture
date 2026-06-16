package mainframe

import (
	"fmt"
	"path/filepath"
	"strings"
)

// TempCertPath returns the USS HFS path for a staging PEM file.
func TempCertPath(assignmentID string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_':
			return r
		default:
			return '-'
		}
	}, strings.TrimSpace(assignmentID))
	if safe == "" {
		safe = "assignment"
	}
	return filepath.Join("/tmp", fmt.Sprintf("compliwise-%s.pem", safe))
}

// BuildTrustCommand returns the RACF trust command line for USS racf execution.
func BuildTrustCommand(racfProfile, certPath string) string {
	profile := strings.TrimSpace(racfProfile)
	path := strings.TrimSpace(certPath)
	return fmt.Sprintf("RACDCERT ID(%s) TRUST WITH(CERT('%s'))", profile, path)
}

// BuildDeleteCommand returns the RACF delete command line for rollback.
func BuildDeleteCommand(racfProfile, label string) string {
	profile := strings.TrimSpace(racfProfile)
	certLabel := strings.TrimSpace(label)
	if certLabel == "" {
		certLabel = "TRUST"
	}
	return fmt.Sprintf("RACDCERT DELETE(%s)-LABEL(%s)", profile, certLabel)
}
