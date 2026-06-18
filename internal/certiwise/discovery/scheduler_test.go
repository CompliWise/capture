package discovery

import (
	"testing"
	"time"

	"github.com/compliwise/capture/internal/certiwise"
	cwconfig "github.com/compliwise/capture/internal/certiwise/config"
)

func TestSchedulerOnDemandTrigger(t *testing.T) {
	scheduler := NewScheduler()
	requested := "2026-06-13T10:00:00Z"
	last := "2026-06-13T08:00:00Z"
	pull := &certiwise.AssignmentsPullResponse{
		DiscoveryScanRequestedAt: &requested,
		LastDiscoveryScanAt:      &last,
	}

	if !scheduler.shouldRunOnDemand(pull) {
		t.Fatal("expected on-demand trigger")
	}
}

func TestSchedulerScheduledBackoff(t *testing.T) {
	scheduler := NewScheduler()
	scheduler.lastLocalScanAt = time.Now().UTC()

	cfg := &cwconfig.Config{DiscoveryInterval: time.Hour}
	if scheduler.shouldRunScheduled(cfg) {
		t.Fatal("expected scheduled scan to be suppressed before interval")
	}
}
