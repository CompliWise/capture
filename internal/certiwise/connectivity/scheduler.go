package connectivity

import (
	"context"
	"log"
	"sync"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

// Scheduler runs connectivity probes when the control plane requests a test.
type Scheduler struct {
	mu       sync.Mutex
	inFlight bool
}

// NewScheduler creates a connectivity test scheduler.
func NewScheduler() *Scheduler {
	return &Scheduler{}
}

// RunIfRequested executes a connectivity probe when the assignment pull flag is set.
func (s *Scheduler) RunIfRequested(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) error {
	if cfg == nil || client == nil || pull == nil || !pull.ConnectivityTestRequested {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	s.mu.Lock()
	if s.inFlight {
		s.mu.Unlock()
		return nil
	}
	s.inFlight = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.inFlight = false
		s.mu.Unlock()
	}()

	steps := RunProbe(ctx, cfg, client)
	if err := SubmitResult(client, steps); err != nil {
		log.Printf("certiwise: connectivity: submit failed: %v", err)
		return err
	}

	return nil
}
