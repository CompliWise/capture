//go:build windows
// +build windows

package discovery

// ScanWindowsCertStore enumerates configured Windows LocalMachine certificate stores.
func ScanWindowsCertStore(opts WindowsScanOptions, maxItems int) []DiscoveredItem {
	return scanWindowsCertStores(opts, maxItems)
}
