package synthetic

import (
	"log"
	"sync"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

// LicenseDeniedLogger rate-limits license-denied warnings to once per hour.
type LicenseDeniedLogger struct {
	mu          sync.Mutex
	lastWarning time.Time
}

func (l *LicenseDeniedLogger) MaybeWarn(err error) {
	if err == nil || !certiwise.IsForbiddenAPIError(err) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.lastWarning) < time.Hour {
		return
	}
	l.lastWarning = time.Now()
	log.Printf("synthetic: telemetry rejected (license): %v", err)
}
