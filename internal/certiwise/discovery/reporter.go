package discovery

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

// LicenseDeniedLogger rate-limits license-denied warnings to once per hour.
type LicenseDeniedLogger struct {
	mu          sync.Mutex
	lastWarning time.Time
}

func (l *LicenseDeniedLogger) MaybeWarn(err error) {
	if err == nil || !certiwise.IsForbiddenAPIError(err) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.lastWarning) < time.Hour {
		return
	}
	l.lastWarning = time.Now()
	log.Printf("certiwise: discovery scan rejected (license): %v", err)
}

// BuildDiscoveryScanEvent constructs a discovery.scan telemetry event.
func BuildDiscoveryScanEvent(result ScanResult, observedAt time.Time) certiwise.TelemetryEvent {
	items := result.Items
	payloadItems := make([]certiwise.DiscoveryScanItem, 0, len(items))
	for _, item := range items {
		payloadItems = append(payloadItems, certiwise.DiscoveryScanItem{
			Source:         item.Source,
			Path:           item.Path,
			Alias:          item.Alias,
			Thumbprint:     strings.ToLower(item.Thumbprint),
			SubjectCN:      item.SubjectCN,
			NotAfter:       item.NotAfter,
			TrustStoreType: item.TrustStoreType,
		})
	}
	payload := certiwise.DiscoveryScanPayload{
		CertificatesFound: len(payloadItems),
		Items:             payloadItems,
	}
	if metadata := certiwiseDiscoveryMetadata(result.Metadata); metadata != nil {
		payload.Metadata = metadata
	}
	return certiwise.TelemetryEvent{
		Type:       "discovery.scan",
		ObservedAt: observedAt.UTC().Format(time.RFC3339),
		Payload:    payload,
	}
}

func certiwiseDiscoveryMetadata(meta ScanMetadata) *certiwise.DiscoveryScanMetadata {
	if !meta.JavaCacertsTruncated && meta.JavaCacertsJvmTotal == 0 && meta.JavaCacertsJvmScanned == 0 {
		return nil
	}
	return &certiwise.DiscoveryScanMetadata{
		JavaCacertsTruncated:  meta.JavaCacertsTruncated,
		JavaCacertsJvmTotal:   meta.JavaCacertsJvmTotal,
		JavaCacertsJvmScanned: meta.JavaCacertsJvmScanned,
	}
}

// PostDiscoveryScan runs a scan and posts discovery.scan telemetry.
func PostDiscoveryScan(
	client *certiwise.Client,
	opts ScanOptions,
	licenseLogger *LicenseDeniedLogger,
) error {
	result := Scan(opts)
	event := BuildDiscoveryScanEvent(result, time.Now())
	err := client.PostTelemetryBatch([]certiwise.TelemetryEvent{event})
	if licenseLogger != nil {
		licenseLogger.MaybeWarn(err)
	}
	return err
}
