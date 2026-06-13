package probe

import (
	"strings"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

// BuildTlsHandshakeEvent constructs a tls.handshake telemetry event.
func BuildTlsHandshakeEvent(
	target ProbeTarget,
	result ProbeResult,
	observedAt time.Time,
) certiwise.TelemetryEvent {
	cipherSuite := normalizeCipherSuite(result.CipherSuite)
	chain := make([]string, len(result.PresentedChainSha256))
	for i, thumbprint := range result.PresentedChainSha256 {
		chain[i] = strings.ToLower(thumbprint)
	}

	event := certiwise.TelemetryEvent{
		Type:       "tls.handshake",
		ObservedAt: observedAt.UTC().Format(time.RFC3339),
		Payload: certiwise.TlsHandshakePayload{
			ServerName:           result.ServerName,
			PeerAddress:          result.PeerAddress,
			TLSVersion:           result.TLSVersion,
			CipherSuite:          cipherSuite,
			PresentedChainSha256: chain,
			ValidationResult:     result.ValidationResult,
			ValidationErrors:     result.ValidationErrors,
			DurationMs:           result.DurationMs,
		},
	}

	if target.ApplicationID != "" {
		event.ApplicationID = target.ApplicationID
	}
	if target.CertificateID != "" {
		event.CertificateID = target.CertificateID
	}
	if target.DeploymentID != "" {
		event.DeploymentID = target.DeploymentID
	}

	return event
}

func normalizeCipherSuite(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "TLS_FALLBACK_SCSV"
	}
	if len(name) > 128 {
		return name[:128]
	}
	return name
}

// PostHandshake posts one tls.handshake telemetry event.
func PostHandshake(
	client *certiwise.Client,
	target ProbeTarget,
	result ProbeResult,
	licenseLogger *LicenseDeniedLogger,
) error {
	event := BuildTlsHandshakeEvent(target, result, time.Now())
	err := client.PostTelemetryBatch([]certiwise.TelemetryEvent{event})
	if licenseLogger != nil {
		licenseLogger.MaybeWarn(err)
	}
	return err
}
