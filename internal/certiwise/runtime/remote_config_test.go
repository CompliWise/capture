package runtime

import (
	"testing"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

func TestRemoteConfigStateApply(t *testing.T) {
	cfg := &cwconfig.Config{
		AgentEnvPath:      t.TempDir() + "/agent.env",
		APIURL:            "http://localhost:4000",
		OrgID:             "org_test",
		AgentID:           "agent_test",
		AgentToken:        "token_test",
		PollInterval:      60 * time.Second,
		HeartbeatInterval: 300 * time.Second,
	}

	state := &remoteConfigState{}
	pull := &certiwise.AssignmentsPullResponse{
		ConfigEtag: "sha256:cfg1",
		Config: certiwise.AgentPullConfig{
			PollIntervalSeconds:      45,
			HeartbeatIntervalSeconds: 90,
			TelemetryBatchSize:       25,
			TelemetryFlushSeconds:    20,
			Enabled:                  true,
		},
	}

	pollChanged, heartbeatChanged := state.apply(cfg, pull)
	if !pollChanged || !heartbeatChanged {
		t.Fatalf("expected interval changes, poll=%v heartbeat=%v", pollChanged, heartbeatChanged)
	}
	if cfg.PollInterval != 45*time.Second {
		t.Fatalf("poll interval = %s", cfg.PollInterval)
	}
	if cfg.HeartbeatInterval != 90*time.Second {
		t.Fatalf("heartbeat interval = %s", cfg.HeartbeatInterval)
	}
	if cfg.TelemetryBatchSize != 25 || cfg.TelemetryFlushSeconds != 20 {
		t.Fatalf("telemetry config not applied: batch=%d flush=%d", cfg.TelemetryBatchSize, cfg.TelemetryFlushSeconds)
	}

	pollChanged, heartbeatChanged = state.apply(cfg, pull)
	if pollChanged || heartbeatChanged {
		t.Fatalf("expected no changes for same config etag")
	}
}

func TestResettableTickerReset(t *testing.T) {
	ticker := newResettableTicker(30 * time.Millisecond)
	defer ticker.Stop()

	ticker.Reset(10 * time.Millisecond)

	deadline := time.After(200 * time.Millisecond)
	count := 0
	for count < 2 {
		select {
		case <-ticker.C:
			count++
		case <-deadline:
			t.Fatalf("expected at least 2 ticks after reset, got %d", count)
		}
	}
}
