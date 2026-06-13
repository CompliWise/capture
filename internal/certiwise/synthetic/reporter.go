package synthetic

import (
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

func intPtr(value int) *int {
	if value < 0 {
		return nil
	}
	return &value
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// BuildSyntheticCheckEvent constructs a synthetic.check telemetry event.
func BuildSyntheticCheckEvent(
	monitorID string,
	result CheckResult,
	observedAt time.Time,
) certiwise.TelemetryEvent {
	return certiwise.TelemetryEvent{
		Type:       "synthetic.check",
		ObservedAt: observedAt.UTC().Format(time.RFC3339),
		Payload: certiwise.SyntheticCheckPayload{
			MonitorID:         monitorID,
			Status:            result.Status,
			ResponseTimeMs:    intPtr(result.ResponseTimeMs),
			CertExpiresAt:     stringPtr(result.CertExpiresAt),
			CertDaysRemaining: intPtr(result.CertDaysRemaining),
			HTTPStatusCode:    intPtr(result.HTTPStatusCode),
			ErrorMessage:      stringPtr(result.ErrorMessage),
		},
	}
}

// PostCheck posts one synthetic.check telemetry event.
func PostCheck(
	client *certiwise.Client,
	monitorID string,
	result CheckResult,
	licenseLogger *LicenseDeniedLogger,
) error {
	event := BuildSyntheticCheckEvent(monitorID, result, time.Now())
	err := client.PostTelemetryBatch([]certiwise.TelemetryEvent{event})
	if licenseLogger != nil {
		licenseLogger.MaybeWarn(err)
	}
	return err
}
