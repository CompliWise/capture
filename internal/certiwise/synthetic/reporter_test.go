package synthetic

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/compliwise/capture/internal/certiwise"
)

func TestBuildSyntheticCheckEventShape(t *testing.T) {
	message := "connection refused"
	event := BuildSyntheticCheckEvent(
		"11111111-1111-4111-8111-111111111111",
		CheckResult{
			Status:            StatusDown,
			ResponseTimeMs:    42,
			HTTPStatusCode:    503,
			CertExpiresAt:     "2026-12-31T00:00:00Z",
			CertDaysRemaining: 180,
			ErrorMessage:      message,
		},
		time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC),
	)

	if event.Type != "synthetic.check" {
		t.Fatalf("expected synthetic.check, got %q", event.Type)
	}

	payload, ok := event.Payload.(certiwise.SyntheticCheckPayload)
	if !ok {
		t.Fatalf("expected SyntheticCheckPayload, got %T", event.Payload)
	}
	if payload.MonitorID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("unexpected monitorId: %q", payload.MonitorID)
	}
	if payload.Status != StatusDown {
		t.Fatalf("expected down status, got %q", payload.Status)
	}
	if payload.ResponseTimeMs == nil || *payload.ResponseTimeMs != 42 {
		t.Fatalf("unexpected responseTimeMs: %v", payload.ResponseTimeMs)
	}
	if payload.ErrorMessage == nil || *payload.ErrorMessage != message {
		t.Fatalf("unexpected errorMessage: %v", payload.ErrorMessage)
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if !json.Valid(encoded) {
		t.Fatalf("invalid json payload")
	}
}
