package discovery

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	linuxSystemCAPath = "/etc/ssl/certs"
	linuxLocalCAPath  = "/usr/local/share/ca-certificates"
)

// ScanLinuxCA collects certificates from Linux system CA directories.
func ScanLinuxCA(maxItems int) []DiscoveredItem {
	if maxItems <= 0 {
		return nil
	}

	var items []DiscoveredItem
	items = append(items, scanCADirectory(linuxSystemCAPath, "linux_system_ca", "linux_update_ca_certificates", maxItems-len(items))...)
	if len(items) >= maxItems {
		return items[:maxItems]
	}
	items = append(items, scanCADirectory(linuxLocalCAPath, "linux_local_ca", "linux_update_ca_certificates", maxItems-len(items))...)
	if len(items) > maxItems {
		return items[:maxItems]
	}
	return items
}

func scanCADirectory(dir, source, trustStoreType string, maxItems int) []DiscoveredItem {
	if maxItems <= 0 {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("certiwise: discovery: skip %s: %v", dir, err)
		return nil
	}

	var items []DiscoveredItem
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if len(items) >= maxItems {
			break
		}

		path := filepath.Join(dir, entry.Name())
		item, err := parseCertFile(path, source, "", trustStoreType)
		if err != nil {
			log.Printf("certiwise: discovery: skip %s: %v", path, err)
			continue
		}
		items = append(items, item)
	}
	return items
}

func parseCertFile(path, source, alias, trustStoreType string) (DiscoveredItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DiscoveredItem{}, err
	}
	cert, err := parseCertificatePEM(data)
	if err != nil {
		return DiscoveredItem{}, err
	}
	item := certToItem(cert, source, path, alias, trustStoreType)
	if strings.TrimSpace(item.Thumbprint) == "" {
		return DiscoveredItem{}, err
	}
	return item, nil
}
