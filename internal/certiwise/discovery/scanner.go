package discovery

// Scan runs all discovery scanners and returns merged, deduped items capped at MaxItems.
func Scan(opts ScanOptions) ScanResult {
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 500
	}

	result := ScanResult{}
	candidates := make([]DiscoveredItem, 0, maxItems)
	candidates = append(candidates, ScanLinuxCA(maxItems)...)
	if len(candidates) < maxItems {
		candidates = append(candidates, ScanPEMGlob(opts.PemPaths, maxItems-len(candidates))...)
	}
	if len(candidates) < maxItems {
		candidates = append(candidates, ScanAssignmentPaths(opts.Assignments, maxItems-len(candidates))...)
	}
	if len(candidates) < maxItems && opts.TLSListener.Enabled {
		remaining := maxItems - len(candidates)
		tlsItems := ScanTLSListeners(opts.TLSListener)
		if len(tlsItems) > remaining {
			tlsItems = tlsItems[:remaining]
		}
		candidates = append(candidates, tlsItems...)
	}
	if len(candidates) < maxItems && opts.Java.Enabled {
		javaItems, javaMeta := ScanJavaCacerts(opts.Java, maxItems-len(candidates))
		candidates = append(candidates, javaItems...)
		result.Metadata = mergeScanMetadata(result.Metadata, javaMeta)
	}
	if len(candidates) < maxItems && opts.Windows.Enabled {
		winItems := ScanWindowsCertStore(opts.Windows, maxItems-len(candidates))
		candidates = append(candidates, winItems...)
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
	result.Items = merged
	return result
}

func mergeScanMetadata(base, extra ScanMetadata) ScanMetadata {
	if extra.JavaCacertsTruncated {
		base.JavaCacertsTruncated = true
	}
	if extra.JavaCacertsJvmTotal > 0 {
		base.JavaCacertsJvmTotal = extra.JavaCacertsJvmTotal
	}
	if extra.JavaCacertsJvmScanned > 0 {
		base.JavaCacertsJvmScanned = extra.JavaCacertsJvmScanned
	}
	return base
}

func dedupeKey(item DiscoveredItem) string {
	return item.Source + "|" + item.Path + "|" + item.Alias + "|" + item.Thumbprint
}
