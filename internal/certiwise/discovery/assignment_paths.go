package discovery

import (
	"log"
	"path/filepath"
	"strings"
)

// ScanAssignmentPaths verifies deployed certificate files for active assignments.
func ScanAssignmentPaths(assignments []AssignmentRef, maxItems int) []DiscoveredItem {
	if maxItems <= 0 {
		return nil
	}

	var items []DiscoveredItem
	for _, assignment := range assignments {
		if len(items) >= maxItems {
			break
		}

		storePath := strings.TrimSpace(assignment.TrustStorePath)
		fileName := strings.TrimSpace(assignment.CertFileName)
		if storePath == "" || fileName == "" {
			continue
		}

		path := filepath.Join(storePath, fileName)
		trustStoreType := strings.TrimSpace(assignment.TrustStoreType)
		if trustStoreType == "" {
			trustStoreType = "linux_update_ca_certificates"
		}

		item, err := parseCertFile(path, "assignment_verify", assignment.Alias, trustStoreType)
		if err != nil {
			log.Printf("certiwise: discovery: assignment verify skip %s: %v", path, err)
			continue
		}
		items = append(items, item)
	}
	return items
}
