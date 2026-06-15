package upgrade

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// State is the agent-side upgrade lifecycle state reported via heartbeat.
type State string

const (
	StatePending      State = "pending"
	StateDownloading  State = "downloading"
	StateVerifying    State = "verifying"
	StateApplying     State = "applying"
	StateCurrent      State = "current"
	StateFailed       State = "failed"
)

// Config controls where upgrades are staged and applied.
type Config struct {
	BinaryPath string
	TempDir    string
}

// PolicyHints are returned by the API heartbeat upgrade directive.
type PolicyHints struct {
	TargetVersion        string
	MaintenanceWindowUtc string
	Force                bool
}

// ArtifactGrant is returned by GET /agent/upgrade-artifact.
type ArtifactGrant struct {
	DownloadURL string
	SHA256      string
	ExpiresAt   string
}

// ArtifactClient fetches upgrade artifacts from the CompliWise API.
type ArtifactClient interface {
	GetUpgradeArtifact(ctx context.Context, targetVersion, platform string) (*ArtifactGrant, error)
}

// Runner orchestrates pending → downloading → verifying → applying transitions.
type Runner struct {
	config Config
	state  State
}

// NewRunner creates an upgrade runner with the provided config.
func NewRunner(config Config) *Runner {
	return &Runner{config: config, state: StatePending}
}

// State returns the current upgrade state.
func (r *Runner) State() State {
	return r.state
}

// Tick evaluates whether an upgrade should run and applies it when allowed.
func (r *Runner) Tick(
	ctx context.Context,
	client ArtifactClient,
	runningVersion string,
	platform string,
	hints PolicyHints,
) (newVersion string, status State, err error) {
	newVersion = runningVersion
	status = r.state
	if hints.TargetVersion == "" {
		r.state = StateCurrent
		return runningVersion, StateCurrent, nil
	}

	if CompareVersions(runningVersion, hints.TargetVersion) >= 0 {
		r.state = StateCurrent
		return runningVersion, StateCurrent, nil
	}

	if !hints.Force && !IsMaintenanceWindowOpen(hints.MaintenanceWindowUtc, time.Now().UTC()) {
		r.state = StatePending
		return runningVersion, StatePending, nil
	}

	r.state = StateDownloading
	status = StateDownloading

	grant, err := client.GetUpgradeArtifact(ctx, hints.TargetVersion, platform)
	if err != nil {
		r.state = StateFailed
		return runningVersion, StateFailed, err
	}

	data, err := downloadHTTPS(ctx, grant.DownloadURL)
	if err != nil {
		r.state = StateFailed
		return runningVersion, StateFailed, err
	}

	r.state = StateVerifying
	status = StateVerifying
	if err := VerifySHA256(data, grant.SHA256); err != nil {
		r.state = StateFailed
		return runningVersion, StateFailed, err
	}

	r.state = StateApplying
	status = StateApplying
	if err := r.applyBinary(data); err != nil {
		r.state = StateFailed
		return runningVersion, StateFailed, err
	}

	r.state = StateCurrent
	return hints.TargetVersion, StateCurrent, nil
}

func downloadHTTPS(ctx context.Context, downloadURL string) ([]byte, error) {
	lowerURL := strings.ToLower(downloadURL)
	if !strings.HasPrefix(lowerURL, "https://") && !strings.HasPrefix(lowerURL, "http://") {
		return nil, fmt.Errorf("upgrade download must use https")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download artifact: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	return data, nil
}

func (r *Runner) applyBinary(data []byte) error {
	binaryPath := strings.TrimSpace(r.config.BinaryPath)
	if binaryPath == "" {
		return fmt.Errorf("binary path is required")
	}

	tempDir := strings.TrimSpace(r.config.TempDir)
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}

	stagedPath := filepath.Join(tempDir, "compliwise-capture-upgrade.bin")
	if err := os.WriteFile(stagedPath, data, 0o755); err != nil {
		return fmt.Errorf("stage upgrade binary: %w", err)
	}

	prevPath := binaryPath + ".prev"
	if _, err := os.Stat(binaryPath); err == nil {
		if err := os.Rename(binaryPath, prevPath); err != nil {
			return fmt.Errorf("backup current binary: %w", err)
		}
	}

	if err := os.Rename(stagedPath, binaryPath); err != nil {
		return fmt.Errorf("apply upgrade binary: %w", err)
	}

	return nil
}
