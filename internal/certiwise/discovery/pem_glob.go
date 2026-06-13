package discovery

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

var pemExtensions = []string{".pem", ".crt", ".cer"}

// ScanPEMGlob collects certificates from configured PEM directories.
func ScanPEMGlob(paths []string, maxItems int) []DiscoveredItem {
	if maxItems <= 0 {
		return nil
	}

	var items []DiscoveredItem
	for _, dir := range paths {
		trimmed := strings.TrimSpace(dir)
		if trimmed == "" {
			continue
		}
		remaining := maxItems - len(items)
		if remaining <= 0 {
			break
		}
		items = append(items, scanPEMDirectory(trimmed, remaining)...)
	}
	if len(items) > maxItems {
		return items[:maxItems]
	}
	return items
}

func scanPEMDirectory(dir string, maxItems int) []DiscoveredItem {
	if maxItems <= 0 {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("certiwise: discovery: skip pem dir %s: %v", dir, err)
		return nil
	}

	var items []DiscoveredItem
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !hasPEMExtension(entry.Name()) {
			continue
		}
		if len(items) >= maxItems {
			break
		}

		path := filepath.Join(dir, entry.Name())
		item, err := parseCertFile(path, "pem_directory", "", "pem_directory")
		if err != nil {
			log.Printf("certiwise: discovery: skip %s: %v", path, err)
			continue
		}
		items = append(items, item)
	}
	return items
}

func hasPEMExtension(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range pemExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
