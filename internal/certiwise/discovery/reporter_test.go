package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

func TestBuildDiscoveryScanEventShape(t *testing.T) {
	observedAt := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	event := BuildDiscoveryScanEvent(ScanResult{
		Items: []DiscoveredItem{
			{
				Source:         "linux_system_ca",
				Path:           "/etc/ssl/certs/test.pem",
				Thumbprint:     "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
				SubjectCN:      "Test CA",
				TrustStoreType: "linux_update_ca_certificates",
			},
		},
	}, observedAt)

	if event.Type != "discovery.scan" {
		t.Fatalf("expected discovery.scan, got %q", event.Type)
	}
	if event.ObservedAt != "2026-06-13T10:00:00Z" {
		t.Fatalf("unexpected observedAt: %q", event.ObservedAt)
	}

	payload, ok := event.Payload.(certiwise.DiscoveryScanPayload)
	if !ok {
		t.Fatalf("expected DiscoveryScanPayload, got %T", event.Payload)
	}
	if payload.CertificatesFound != 1 {
		t.Fatalf("expected certificatesFound=1, got %d", payload.CertificatesFound)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(payload.Items))
	}
	if payload.Items[0].Thumbprint != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Fatalf("expected lowercase thumbprint, got %q", payload.Items[0].Thumbprint)
	}
}

func TestBuildDiscoveryScanEventIncludesMetadata(t *testing.T) {
	observedAt := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	event := BuildDiscoveryScanEvent(ScanResult{
		Metadata: ScanMetadata{
			JavaCacertsTruncated:  true,
			JavaCacertsJvmTotal:   8,
			JavaCacertsJvmScanned: 5,
		},
	}, observedAt)

	payload, ok := event.Payload.(certiwise.DiscoveryScanPayload)
	if !ok {
		t.Fatalf("expected DiscoveryScanPayload, got %T", event.Payload)
	}
	if payload.Metadata == nil {
		t.Fatal("expected metadata on payload")
	}
	if !payload.Metadata.JavaCacertsTruncated {
		t.Fatal("expected javaCacertsTruncated=true")
	}
	if payload.Metadata.JavaCacertsJvmTotal != 8 {
		t.Fatalf("expected jvm total 8, got %d", payload.Metadata.JavaCacertsJvmTotal)
	}
}

func TestPostDiscoveryScanPostsBatch(t *testing.T) {
	var received certiwise.TelemetryEvent

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []certiwise.TelemetryEvent `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(body.Events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(body.Events))
		}
		received = body.Events[0]
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client, err := certiwise.NewClient(certiwise.ClientConfig{
		BaseURL:    server.URL,
		AgentToken: "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	err = PostDiscoveryScan(client, ScanOptions{MaxItems: 10}, nil)
	if err != nil {
		t.Fatalf("PostDiscoveryScan: %v", err)
	}
	if received.Type != "discovery.scan" {
		t.Fatalf("expected discovery.scan, got %q", received.Type)
	}
}
