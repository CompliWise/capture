package discovery

// Scan runs all discovery scanners and returns merged, deduped items capped at MaxItems.
func Scan(opts ScanOptions) []DiscoveredItem {
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 500
	}

	candidates := make([]DiscoveredItem, 0, maxItems)
	candidates = append(candidates, ScanLinuxCA(maxItems)...)
	if len(candidates) < maxItems {
		candidates = append(candidates, ScanPEMGlob(opts.PemPaths, maxItems-len(candidates))...)
	}
	if len(candidates) < maxItems {
		candidates = append(candidates, ScanAssignmentPaths(opts.Assignments, maxItems-len(candidates))...)
	}

	seen := make(map[string]struct{}, len(candidates))
	merged := make([]DiscoveredItem, 0, len(candidates))
	for _, item := range candidates {
		key := dedupeKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, item)
		if len(merged) >= maxItems {
			break
		}
	}
	return merged
}

func dedupeKey(item DiscoveredItem) string {
	return item.Source + "|" + item.Path + "|" + item.Alias + "|" + item.Thumbprint
}
