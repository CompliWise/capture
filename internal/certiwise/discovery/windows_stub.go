//go:build !windows
// +build !windows

package discovery

// ScanWindowsCertStore enumerates Windows certificate stores when an executor is injected (tests).
func ScanWindowsCertStore(opts WindowsScanOptions, maxItems int) []DiscoveredItem {
	if opts.Executor != nil {
		return scanWindowsCertStores(opts, maxItems)
	}
	return nil
}
