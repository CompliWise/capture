package runtime

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	"github.com/bluewave-labs/capture/internal/upgrade"
)

type heartbeatState struct {
	upgradeStatus string
}

func newHeartbeatState() *heartbeatState {
	return &heartbeatState{}
}

type certiwiseArtifactClient struct {
	client *certiwise.Client
}

func (c certiwiseArtifactClient) GetUpgradeArtifact(
	_ context.Context,
	targetVersion, platform string,
) (*upgrade.ArtifactGrant, error) {
	resp, err := c.client.GetUpgradeArtifact(context.Background(), targetVersion, platform)
	if err != nil {
		return nil, err
	}
	return &upgrade.ArtifactGrant{
		DownloadURL: resp.DownloadURL,
		SHA256:      resp.SHA256,
		ExpiresAt:   resp.ExpiresAt,
	}, nil
}

func maybeRunUpgrade(
	ctx context.Context,
	client *certiwise.Client,
	platform string,
	agentVersion string,
	state *heartbeatState,
	resp *certiwise.HeartbeatResponse,
) string {
	if resp == nil || resp.Upgrade == nil || resp.Upgrade.TargetVersion == "" {
		return agentVersion
	}

	runner := upgrade.NewRunner(upgrade.Config{
		BinaryPath: platformBinaryPath(),
		TempDir:    "",
	})

	newVersion, status, err := runner.Tick(
		ctx,
		certiwiseArtifactClient{client: client},
		agentVersion,
		platform,
		upgrade.PolicyHints{
			TargetVersion:        resp.Upgrade.TargetVersion,
			MaintenanceWindowUtc: resp.Upgrade.MaintenanceWindowUTC,
			Force:                resp.Upgrade.Force,
		},
	)
	if err != nil {
		log.Printf("certiwise: upgrade step failed: %v", err)
	}

	if state != nil {
		state.upgradeStatus = string(status)
	}

	if status == upgrade.StateFailed {
		_, hbErr := client.Heartbeat(certiwise.HeartbeatRequest{
			AgentVersion:  agentVersion,
			Platform:      platform,
			UpgradeStatus: string(status),
			UpgradeError:  err.Error(),
		})
		if hbErr != nil {
			log.Printf("certiwise: failed upgrade heartbeat failed: %v", hbErr)
		}
		return agentVersion
	}

	if newVersion != agentVersion && status == upgrade.StateCurrent {
		_, hbErr := client.Heartbeat(certiwise.HeartbeatRequest{
			AgentVersion:  newVersion,
			Platform:      platform,
			UpgradeStatus: string(status),
			LastUpgradeAt: time.Now().UTC().Format(time.RFC3339),
		})
		if hbErr != nil {
			log.Printf("certiwise: post-upgrade heartbeat failed: %v", hbErr)
		}
		return newVersion
	}

	if state != nil && status == upgrade.StatePending {
		_, hbErr := client.Heartbeat(certiwise.HeartbeatRequest{
			AgentVersion:  agentVersion,
			Platform:      platform,
			UpgradeStatus: string(status),
		})
		if hbErr != nil {
			log.Printf("certiwise: pending upgrade heartbeat failed: %v", hbErr)
		}
	}

	return agentVersion
}

func platformBinaryPath() string {
	if path := os.Getenv("COMPLIWISE_BINARY_PATH"); path != "" {
		return path
	}
	return os.Args[0]
}
