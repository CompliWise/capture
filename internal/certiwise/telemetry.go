package certiwise

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const telemetryBatchPath = "/api/v1/agent/telemetry/batch"

// TelemetryEvent is one event in a telemetry batch POST.
type TelemetryEvent struct {
	Type          string `json:"type"`
	ObservedAt    string `json:"observedAt"`
	ApplicationID string `json:"applicationId,omitempty"`
	CertificateID string `json:"certificateId,omitempty"`
	DeploymentID  string `json:"deploymentId,omitempty"`
	Payload       any    `json:"payload"`
}

// TlsHandshakePayload is the tls.handshake event payload.
type TlsHandshakePayload struct {
	ServerName           string   `json:"serverName"`
	PeerAddress          string   `json:"peerAddress"`
	TLSVersion           string   `json:"tlsVersion"`
	CipherSuite          string   `json:"cipherSuite"`
	PresentedChainSha256 []string `json:"presentedChainSha256"`
	ValidationResult     string   `json:"validationResult"`
	ValidationErrors     []string `json:"validationErrors"`
	DurationMs           int      `json:"durationMs"`
}

// SyntheticCheckPayload is the synthetic.check event payload.
type SyntheticCheckPayload struct {
	MonitorID         string  `json:"monitorId"`
	Status            string  `json:"status"`
	ResponseTimeMs    *int    `json:"responseTimeMs"`
	CertExpiresAt     *string `json:"certExpiresAt"`
	CertDaysRemaining *int    `json:"certDaysRemaining"`
	HTTPStatusCode    *int    `json:"httpStatusCode"`
	ErrorMessage      *string `json:"errorMessage"`
}

// DiscoveryScanMetadata is optional discovery.scan payload metadata.
type DiscoveryScanMetadata struct {
	JavaCacertsTruncated  bool `json:"javaCacertsTruncated,omitempty"`
	JavaCacertsJvmTotal   int  `json:"javaCacertsJvmTotal,omitempty"`
	JavaCacertsJvmScanned int  `json:"javaCacertsJvmScanned,omitempty"`
}

// DiscoveryScanPayload is the discovery.scan event payload.
type DiscoveryScanPayload struct {
	CertificatesFound int                    `json:"certificatesFound"`
	Items             []DiscoveryScanItem    `json:"items"`
	Metadata          *DiscoveryScanMetadata `json:"metadata,omitempty"`
}

// DiscoveryScanItem is one discovered certificate in telemetry.
type DiscoveryScanItem struct {
	Source         string `json:"source"`
	Path           string `json:"path,omitempty"`
	Alias          string `json:"alias,omitempty"`
	Thumbprint     string `json:"thumbprint"`
	SubjectCN      string `json:"subjectCn,omitempty"`
	NotAfter       string `json:"notAfter,omitempty"`
	TrustStoreType string `json:"trustStoreType,omitempty"`
}

type telemetryBatchRequest struct {
	Events []TelemetryEvent `json:"events"`
}

// TelemetryBatchError is returned when telemetry ingest is rejected by the API.
type TelemetryBatchError struct {
	StatusCode int
	Message    string
}

func (e *TelemetryBatchError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("telemetry batch failed with status %d", e.StatusCode)
}

// PostTelemetryBatch ingests one or more telemetry events.
func (c *Client) PostTelemetryBatch(events []TelemetryEvent) error {
	if len(events) == 0 {
		return fmt.Errorf("telemetry batch requires at least one event")
	}

	encoded, err := json.Marshal(telemetryBatchRequest{Events: events})
	if err != nil {
		return fmt.Errorf("marshal telemetry batch: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+telemetryBatchPath, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create telemetry request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token == "" {
		return fmt.Errorf("agent token is required")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", telemetryBatchPath, err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read telemetry response: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	var apiErr apiError
	message := strings.TrimSpace(string(responseBody))
	if err := json.Unmarshal(responseBody, &apiErr); err == nil && apiErr.Message != "" {
		message = apiErr.Message
	}
	if len(message) > 256 {
		message = message[:256] + "..."
	}

	return &TelemetryBatchError{
		StatusCode: resp.StatusCode,
		Message:    message,
	}
}

// IsForbiddenAPIError reports whether an API client error is an HTTP 403 response.
func IsForbiddenAPIError(err error) bool {
	if batchErr, ok := err.(*TelemetryBatchError); ok {
		return batchErr.StatusCode == http.StatusForbidden
	}
	return err != nil && strings.Contains(err.Error(), "status 403")
}
