package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

func TestProbeHandshakeCapturesChainThumbprints(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hostOnly, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	result := ProbeHandshake(context.Background(), ProbeTarget{
		Host:       hostOnly,
		Port:       port,
		ServerName: hostOnly,
	}, HandshakeOptions{
		Timeout:            5 * time.Second,
		InsecureSkipVerify: true,
	})

	if result.DialError != nil {
		t.Fatalf("ProbeHandshake dial error: %v", result.DialError)
	}
	if len(result.ChainSHA256) == 0 {
		t.Fatal("expected chain thumbprints")
	}
	if len(result.ChainSHA256[0]) != 64 {
		t.Fatalf("expected 64-char thumbprint, got %q", result.ChainSHA256[0])
	}
	if result.TLSVersion == "" {
		t.Fatal("expected tls version")
	}
}

func TestProbeDialFailure(t *testing.T) {
	result := Probe(context.Background(), ProbeTarget{
		Host:       "127.0.0.1",
		Port:       1,
		ServerName: "missing.example",
	}, &cwconfig.Config{ProbeTimeout: time.Second})

	if result.ValidationResult != validationHandshakeError {
		t.Fatalf("expected handshake_error, got %q", result.ValidationResult)
	}
	if len(result.PresentedChainSha256) == 0 {
		t.Fatal("expected placeholder chain thumbprint")
	}
}

func TestValidateHandshakeMapsDialFailure(t *testing.T) {
	outcome := ValidateHandshake(HandshakeResult{
		DialError: context.DeadlineExceeded,
	}, "example.com", false)
	if outcome.Result != validationHandshakeError {
		t.Fatalf("expected handshake_error, got %q", outcome.Result)
	}
}
