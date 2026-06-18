package certiwise

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPostTelemetryBatch(t *testing.T) {
	var received telemetryBatchRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != telemetryBatchPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("expected bearer token, got %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    server.URL,
		AgentToken: "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = client.PostTelemetryBatch([]TelemetryEvent{
		{
			Type:       "discovery.scan",
			ObservedAt: "2026-06-13T10:00:00Z",
			Payload: map[string]any{
				"certificatesFound": 1,
				"items": []map[string]any{
					{
						"source":     "linux_system_ca",
						"path":       "/etc/ssl/certs/test.pem",
						"thumbprint": strings.Repeat("a", 64),
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("PostTelemetryBatch: %v", err)
	}

	if len(received.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received.Events))
	}
	if received.Events[0].Type != "discovery.scan" {
		t.Fatalf("expected discovery.scan, got %q", received.Events[0].Type)
	}
}

func TestPostTelemetryBatchLicenseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(apiError{Message: "This feature is not included in your plan. Upgrade to unlock it."})
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    server.URL,
		AgentToken: "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = client.PostTelemetryBatch([]TelemetryEvent{
		{Type: "discovery.scan", ObservedAt: "2026-06-13T10:00:00Z", Payload: map[string]any{"certificatesFound": 0, "items": []any{}}},
	})
	var batchErr *TelemetryBatchError
	if !errors.As(err, &batchErr) {
		t.Fatalf("expected TelemetryBatchError, got %T: %v", err, err)
	}
	if batchErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", batchErr.StatusCode)
	}
}
