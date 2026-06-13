package synthetic

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

// SyncMonitors pulls monitor assignments and reconciles the runner pool.
func SyncMonitors(
	ctx context.Context,
	client *certiwise.Client,
	runner *Runner,
	cfg *cwconfig.Config,
	agentVersion string,
) error {
	if cfg == nil || !cfg.SyntheticEnabled || client == nil || runner == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	resp, err := client.PullSyntheticMonitors()
	if err != nil {
		return fmt.Errorf("pull synthetic monitors: %w", err)
	}

	monitors := make([]Monitor, 0, len(resp.Monitors))
	for _, item := range resp.Monitors {
		monitors = append(monitors, MonitorFromAPI(item))
	}

	userAgent := syntheticUserAgent(cfg, agentVersion)
	runner.Sync(ctx, client, cfg, monitors, userAgent)
	log.Printf("synthetic: synced %d monitors", len(monitors))
	return nil
}

// MonitorFromAPI maps an API monitor row to the runner monitor type.
func MonitorFromAPI(item certiwise.SyntheticMonitorPullItem) Monitor {
	assertions := Assertions{
		MinTlsVersion:      item.Assertions.MinTlsVersion,
		MaxDaysUntilExpiry: item.Assertions.MaxDaysUntilExpiry,
		ExpectedSan:        item.Assertions.ExpectedSan,
		MaxResponseTimeMs:  item.Assertions.MaxResponseTimeMs,
		ExpectHttpStatus:   item.Assertions.ExpectHttpStatus,
	}
	return Monitor{
		ID:              item.ID,
		URL:             item.URL,
		IntervalSeconds: item.IntervalSeconds,
		TimeoutMs:       item.TimeoutMs,
		Assertions:      assertions,
	}
}

func syntheticUserAgent(cfg *cwconfig.Config, agentVersion string) string {
	if cfg == nil {
		return ""
	}
	template := cfg.SyntheticUserAgent
	if template == "" {
		template = "CompliWise-Capture-Agent/{version}"
	}
	version := agentVersion
	if version == "" {
		version = "0.0.0"
	}
	return replaceVersionToken(template, version)
}

func replaceVersionToken(template, version string) string {
	if template == "" {
		return ""
	}
	if version == "" {
		version = "0.0.0"
	}
	return strings.ReplaceAll(template, "{version}", version)
}
