package runtime

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/bluewave-labs/capture/internal/certiwise"
	"github.com/bluewave-labs/capture/internal/installer/linux"
)

type assignmentTracker struct {
	mu                   sync.Mutex
	processedDeployments map[string]struct{}
}

func newAssignmentTracker() *assignmentTracker {
	return &assignmentTracker{
		processedDeployments: make(map[string]struct{}),
	}
}

func (t *assignmentTracker) isSucceeded(deploymentID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, seen := t.processedDeployments[deploymentID]
	return seen
}

func (t *assignmentTracker) markSucceeded(deploymentID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.processedDeployments[deploymentID] = struct{}{}
}

func syncAssignments(
	ctx context.Context,
	client *certiwise.Client,
	tracker *assignmentTracker,
) (*certiwise.AssignmentsPullResponse, []certiwise.AssignmentPullItem, error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	pull, err := client.PullAssignments()
	if err != nil {
		return nil, nil, fmt.Errorf("pull assignments: %w", err)
	}

	succeeded := make([]certiwise.AssignmentPullItem, 0)
	for _, assignment := range pull.Assignments {
		if tracker.isSucceeded(assignment.DeploymentID) {
			continue
		}

		if err := processAssignment(ctx, client, assignment); err != nil {
			log.Printf(
				"certiwise: assignment %s deployment %s failed: %v",
				assignment.AssignmentID,
				assignment.DeploymentID,
				err,
			)
			continue
		}

		tracker.markSucceeded(assignment.DeploymentID)
		succeeded = append(succeeded, assignment)
	}

	return pull, succeeded, nil
}

func processAssignment(
	ctx context.Context,
	client *certiwise.Client,
	assignment certiwise.AssignmentPullItem,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	finishedAt := certiwise.NowISO()
	report := func(status, errorCode, errorMessage, installerLog string) {
		req := certiwise.DeploymentReportRequest{
			Status:       status,
			ErrorCode:    errorCode,
			ErrorMessage: errorMessage,
			InstallerLog: installerLog,
			FinishedAt:   finishedAt,
		}
		if err := client.ReportDeployment(assignment.DeploymentID, req); err != nil {
			log.Printf(
				"certiwise: report deployment %s (%s): %v",
				assignment.DeploymentID,
				status,
				err,
			)
		}
	}

	switch assignment.TrustStoreType {
	case "linux_update_ca_certificates":
		if assignment.MaterialType != "trust_anchor" {
			report(
				"failed",
				"ERR_INSTALL_FAILED",
				"linux_update_ca_certificates only supports trust_anchor material",
				"",
			)
			return fmt.Errorf("unsupported material type %q", assignment.MaterialType)
		}

		installerLog, err := linux.InstallLinuxUpdateCACertificates(linux.InstallOptions{
			CertFileName:   assignment.Config.CertFileName,
			TrustStorePath: assignment.Config.TrustStorePath,
			ReloadCommand:  assignment.Config.ReloadCommand,
			ChainPem:       assignment.Material.ChainPem,
		})
		if err != nil {
			report("failed", "ERR_INSTALL_FAILED", err.Error(), installerLog)
			return err
		}

		report("succeeded", "", "", installerLog)
		log.Printf(
			"certiwise: installed trust anchor for assignment %s at %s",
			assignment.AssignmentID,
			assignment.Config.Alias,
		)
		return nil
	default:
		message := fmt.Sprintf("trust store type %q is not supported by this agent build", assignment.TrustStoreType)
		report("failed", "ERR_INSTALL_FAILED", message, "")
		return fmt.Errorf("%s", message)
	}
}
