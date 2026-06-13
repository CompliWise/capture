package probe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

func TestBuildTlsHandshakeEventShape(t *testing.T) {
	observedAt := time.Date(2026, 6, 13, 10, 5, 0, 0, time.UTC)
	event := BuildTlsHandshakeEvent(
		ProbeTarget{
			ApplicationID: "app-payment-api",
			CertificateID: "cert-abc123",
			DeploymentID:  "dep-uuid",
			ServerName:    "e2e-probe",
		},
		ProbeResult{
			ServerName:           "e2e-probe",
			PeerAddress:          "172.18.0.5:443",
			TLSVersion:           "TLS1.3",
			CipherSuite:          "TLS_AES_128_GCM_SHA256",
			PresentedChainSha256: []string{"A" + strings.Repeat("1", 63)},
			ValidationResult:     validationOK,
			ValidationErrors:     nil,
			DurationMs:           42,
		},
		observedAt,
	)

	if event.Type != "tls.handshake" {
		t.Fatalf("expected tls.handshake, got %q", event.Type)
	}
	if event.ApplicationID != "app-payment-api" {
		t.Fatalf("unexpected applicationId: %q", event.ApplicationID)
	}
	if event.DeploymentID != "dep-uuid" {
		t.Fatalf("unexpected deploymentId: %q", event.DeploymentID)
	}

	payload, ok := event.Payload.(certiwise.TlsHandshakePayload)
	if !ok {
		t.Fatalf("expected TlsHandshakePayload, got %T", event.Payload)
	}
	if payload.ValidationResult != validationOK {
		t.Fatalf("expected ok validation, got %q", payload.ValidationResult)
	}
	if payload.PresentedChainSha256[0] != "a"+strings.Repeat("1", 63) {
		t.Fatalf("expected lowercase thumbprint, got %q", payload.PresentedChainSha256[0])
	}
}

func TestPostHandshakePostsBatch(t *testing.T) {
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

	err = PostHandshake(client, ProbeTarget{ServerName: "probe.example"}, ProbeResult{
		ServerName:           "probe.example",
		PeerAddress:          "127.0.0.1:443",
		TLSVersion:           "TLS1.3",
		CipherSuite:          "TLS_AES_128_GCM_SHA256",
		PresentedChainSha256: []string{strings.Repeat("b", 64)},
		ValidationResult:     validationOK,
		DurationMs:           10,
	}, nil)
	if err != nil {
		t.Fatalf("PostHandshake: %v", err)
	}
	if received.Type != "tls.handshake" {
		t.Fatalf("expected tls.handshake, got %q", received.Type)
	}
}
