package synthetic

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

// Runner manages per-monitor check goroutines with a worker pool cap.
type Runner struct {
	mu            sync.Mutex
	workers       chan struct{}
	active        map[string]context.CancelFunc
	licenseLogger LicenseDeniedLogger
}

// NewRunner creates a synthetic monitor runner.
func NewRunner(maxWorkers int) *Runner {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	return &Runner{
		workers: make(chan struct{}, maxWorkers),
		active:  make(map[string]context.CancelFunc),
	}
}

// ActiveCount returns the number of running monitor goroutines.
func (r *Runner) ActiveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}

// Sync reconciles running goroutines with the latest monitor list.
func (r *Runner) Sync(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	monitors []Monitor,
	userAgent string,
) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	nextIDs := make(map[string]struct{}, len(monitors))
	for _, monitor := range monitors {
		nextIDs[monitor.ID] = struct{}{}
		cancel, exists := r.active[monitor.ID]
		if exists {
			cancel()
		}
		monitorCtx, monitorCancel := context.WithCancel(ctx)
		r.active[monitor.ID] = monitorCancel
		go r.runMonitor(monitorCtx, client, cfg, monitor, userAgent)
	}

	for id, cancel := range r.active {
		if _, ok := nextIDs[id]; !ok {
			cancel()
			delete(r.active, id)
		}
	}
}

// StopAll cancels every running monitor goroutine.
func (r *Runner) StopAll() {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for id, cancel := range r.active {
		cancel()
		delete(r.active, id)
	}
}

func (r *Runner) runMonitor(
	ctx context.Context,
	client *certiwise.Client,
	cfg *cwconfig.Config,
	monitor Monitor,
	userAgent string,
) {
	interval := time.Duration(monitor.IntervalSeconds) * time.Second
	if interval < time.Minute {
		interval = time.Minute
	}

	r.executeCheck(ctx, client, monitor, userAgent)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.executeCheck(ctx, client, monitor, userAgent)
		}
	}
}

func (r *Runner) executeCheck(
	ctx context.Context,
	client *certiwise.Client,
	monitor Monitor,
	userAgent string,
) {
	select {
	case r.workers <- struct{}{}:
	case <-ctx.Done():
		return
	}

	defer func() { <-r.workers }()

	result := RunCheck(ctx, monitor, userAgent)
	if err := PostCheck(client, monitor.ID, result, &r.licenseLogger); err != nil {
		log.Printf("synthetic: post check for %s failed: %v", monitor.ID, err)
		return
	}
	log.Printf("synthetic: posted check for %s status=%s", monitor.ID, result.Status)
}
