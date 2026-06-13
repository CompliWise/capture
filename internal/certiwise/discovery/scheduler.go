package discovery

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

// Scheduler coordinates discovery scan triggers.
type Scheduler struct {
	mu              sync.Mutex
	lastLocalScanAt time.Time
	licenseLogger   LicenseDeniedLogger
}

// NewScheduler creates a discovery scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{}
}

// RunIfDue executes a discovery scan when on-demand or scheduled triggers fire.
func (s *Scheduler) RunIfDue(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) error {
	if cfg == nil || !cfg.DiscoveryEnabled || pull == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	onDemand := s.shouldRunOnDemand(pull)
	scheduled := s.shouldRunScheduled(cfg)
	if !onDemand && !scheduled {
		return nil
	}

	return s.runScan(ctx, client, cfg, pull)
}

// RunPostDeploy executes a discovery scan after a successful deployment.
func (s *Scheduler) RunPostDeploy(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) error {
	if cfg == nil || !cfg.DiscoveryEnabled || !cfg.DiscoveryPostDeploy || pull == nil {
		return nil
	}
	return s.runScan(ctx, client, cfg, pull)
}

func (s *Scheduler) shouldRunOnDemand(pull *certiwise.AssignmentsPullResponse) bool {
	return OnDemandDue(pull.DiscoveryRequestedAt(), pull.LastDiscoveryAt())
}

// OnDemandDue reports whether an on-demand discovery scan should run.
func OnDemandDue(requestedAt, lastScanAt string) bool {
	requestedAt = strings.TrimSpace(requestedAt)
	lastScanAt = strings.TrimSpace(lastScanAt)
	if requestedAt == "" {
		return false
	}
	if lastScanAt == "" {
		return true
	}
	requested, errRequested := time.Parse(time.RFC3339, requestedAt)
	last, errLast := time.Parse(time.RFC3339, lastScanAt)
	if errRequested != nil {
		return false
	}
	if errLast != nil {
		return true
	}
	return requested.After(last)
}

func (s *Scheduler) shouldRunScheduled(cfg *cwconfig.Config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastLocalScanAt.IsZero() {
		return true
	}
	return time.Since(s.lastLocalScanAt) >= cfg.DiscoveryInterval
}

func (s *Scheduler) runScan(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) error {
	s.mu.Lock()
	if !s.lastLocalScanAt.IsZero() && time.Since(s.lastLocalScanAt) < 30*time.Second {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	opts := ScanOptions{
		PemPaths:    cfg.DiscoveryPemPaths,
		MaxItems:    cfg.DiscoveryMaxItems,
		Assignments: assignmentsFromPull(pull),
		TLSListener: TLSListenerOptions{
			Enabled:             cfg.DiscoveryTLSEnabled,
			Hosts:               cfg.DiscoveryTLSHosts,
			StaticPorts:         cfg.DiscoveryTLSPorts,
			StaticPortsExplicit: cfg.DiscoveryTLSPortsExplicit,
			PortRange:           cfg.DiscoveryTLSPortRange,
			Timeout:             cfg.DiscoveryTLSTimeout,
			Insecure:            cfg.DiscoveryTLSInsecure,
			MaxWorkers:          5,
			Assignments:         pull.Assignments,
		},
	}

	err := PostDiscoveryScan(client, opts, &s.licenseLogger)
	if err != nil {
		var batchErr *certiwise.TelemetryBatchError
		if errors.As(err, &batchErr) && batchErr.StatusCode == 403 {
			return nil
		}
		return err
	}

	s.mu.Lock()
	s.lastLocalScanAt = time.Now().UTC()
	s.mu.Unlock()

	log.Printf("certiwise: discovery: posted scan")
	return nil
}

func assignmentsFromPull(pull *certiwise.AssignmentsPullResponse) []AssignmentRef {
	assignments := make([]AssignmentRef, 0, len(pull.Assignments))
	for _, item := range pull.Assignments {
		assignments = append(assignments, AssignmentRef{
			Alias:            item.Config.Alias,
			TrustStorePath:   item.Config.TrustStorePath,
			CertFileName:     item.Config.CertFileName,
			TrustStoreType:   item.TrustStoreType,
			VerifyEndpoint:   item.Config.VerifyEndpoint,
		})
	}
	return assignments
}
