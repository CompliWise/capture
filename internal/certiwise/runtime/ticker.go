package runtime

import "time"

// resettableTicker exposes a channel that fires on a resettable interval.
type resettableTicker struct {
	C      <-chan time.Time
	reset  chan time.Duration
	stop   chan struct{}
	stopped chan struct{}
}

func newResettableTicker(interval time.Duration) *resettableTicker {
	if interval <= 0 {
		interval = time.Second
	}
	out := make(chan time.Time, 1)
	rt := &resettableTicker{
		C:      out,
		reset:  make(chan time.Duration, 1),
		stop:   make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go rt.loop(out, interval)
	return rt
}

func (rt *resettableTicker) loop(out chan<- time.Time, interval time.Duration) {
	defer close(rt.stopped)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rt.stop:
			return
		case next := <-rt.reset:
			if next <= 0 {
				continue
			}
			if next == interval {
				continue
			}
			interval = next
			ticker.Stop()
			ticker = time.NewTicker(interval)
		case tick := <-ticker.C:
			out <- tick
		}
	}
}

func (rt *resettableTicker) Reset(interval time.Duration) {
	if interval <= 0 {
		return
	}
	select {
	case rt.reset <- interval:
	default:
	}
}

func (rt *resettableTicker) Stop() {
	close(rt.stop)
	<-rt.stopped
}
