package probe

import (
	"context"
	"testing"
	"time"

	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

func TestProbeDialFailureUsesSentinelThumbprint(t *testing.T) {
	cfg := &cwconfig.Config{ProbeTimeout: time.Second}
	result := Probe(context.Background(), ProbeTarget{
		ServerName: "missing.example",
		Host:       "127.0.0.1",
		Port:       1,
	}, cfg)

	if result.ValidationResult != validationHandshakeError {
		t.Fatalf("expected handshake_error, got %q", result.ValidationResult)
	}
	if len(result.PresentedChainSha256) != 1 {
		t.Fatalf("expected sentinel thumbprint, got %v", result.PresentedChainSha256)
	}
	if result.PresentedChainSha256[0] != handshakeErrorThumbprint {
		t.Fatalf("expected zero thumbprint sentinel, got %q", result.PresentedChainSha256[0])
	}
}
