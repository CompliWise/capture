package synthetic

import (
	"context"
	"testing"
	"time"

	"github.com/compliwise/capture/internal/certiwise"
	cwconfig "github.com/compliwise/capture/internal/certiwise/config"
)

func TestRunnerSyncStartsAndStopsMonitors(t *testing.T) {
	runner := NewRunner(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &certiwise.Client{}
	cfg := &cwconfig.Config{}

	runner.Sync(ctx, client, cfg, []Monitor{
		{ID: "mon-1", URL: "https://example.com", IntervalSeconds: 60, TimeoutMs: 1000},
		{ID: "mon-2", URL: "https://example.org", IntervalSeconds: 60, TimeoutMs: 1000},
	}, "test-agent/1.0")

	deadline := time.Now().Add(500 * time.Millisecond)
	for runner.ActiveCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runner.ActiveCount() != 2 {
		t.Fatalf("expected 2 active monitors, got %d", runner.ActiveCount())
	}

	runner.Sync(ctx, client, cfg, nil, "test-agent/1.0")

	deadline = time.Now().Add(500 * time.Millisecond)
	for runner.ActiveCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runner.ActiveCount() != 0 {
		t.Fatalf("expected 0 active monitors after sync, got %d", runner.ActiveCount())
	}
}
