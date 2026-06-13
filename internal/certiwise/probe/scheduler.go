package probe

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

// Scheduler coordinates TLS probe triggers.
type Scheduler struct {
	mu            sync.Mutex
	lastRun       time.Time
	licenseLogger LicenseDeniedLogger
}

// NewScheduler creates a TLS probe scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{}
}

// RunAll probes every resolved target and posts telemetry.
func (s *Scheduler) RunAll(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) error {
	if cfg == nil || !cfg.ProbeEnabled || client == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	s.mu.Lock()
	if !s.lastRun.IsZero() && time.Since(s.lastRun) < 30*time.Second {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	targets, err := ResolveTargetsFromConfig(cfg, pull)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}

	var firstErr error
	for _, target := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		result := Probe(ctx, target, cfg)
		if err := PostHandshake(client, target, result, &s.licenseLogger); err != nil {
			var batchErr *certiwise.TelemetryBatchError
			if errors.As(err, &batchErr) && batchErr.StatusCode == 403 {
				return nil
			}
			if firstErr == nil {
				firstErr = err
			}
			log.Printf("probe: post handshake for %s failed: %v", target.ServerName, err)
			continue
		}
		log.Printf("probe: posted tls.handshake for %s (%s)", target.ServerName, result.ValidationResult)
	}

	s.mu.Lock()
	s.lastRun = time.Now().UTC()
	s.mu.Unlock()

	return firstErr
}

// RunIfDue executes probes when the configured interval has elapsed.
func (s *Scheduler) RunIfDue(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) error {
	if cfg == nil || !cfg.ProbeEnabled {
		return nil
	}

	s.mu.Lock()
	due := s.lastRun.IsZero() || time.Since(s.lastRun) >= cfg.ProbeInterval
	s.mu.Unlock()
	if !due {
		return nil
	}

	return s.RunAll(ctx, client, cfg, pull)
}

// RunManual executes an immediate probe cycle for operator debug APIs.
func (s *Scheduler) RunManual(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) (int, error) {
	targets, err := ResolveTargetsFromConfig(cfg, pull)
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, nil
	}
	return len(targets), s.RunAll(ctx, client, cfg, pull)
}

// RunPostDeploy probes the assignment verify endpoint after a successful deployment.
func (s *Scheduler) RunPostDeploy(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	assignment certiwise.AssignmentPullItem,
) error {
	if cfg == nil || !cfg.ProbeEnabled || !cfg.ProbePostDeploy || client == nil {
		return nil
	}

	target, ok := TargetFromAssignment(assignment)
	if !ok {
		return nil
	}

	result := Probe(ctx, target, cfg)
	return PostHandshake(client, target, result, &s.licenseLogger)
}
