package probe

import (
	"context"
	"errors"
)

var manualRunner func(context.Context) (int, error)

// RegisterManualRunner wires the runtime scheduler for local manual probes.
func RegisterManualRunner(fn func(context.Context) (int, error)) {
	manualRunner = fn
}

// TriggerManual executes a manual TLS probe when a runner is registered.
func TriggerManual(ctx context.Context) (int, error) {
	if manualRunner == nil {
		return 0, errors.New("probe runner is not configured")
	}
	return manualRunner(ctx)
}
