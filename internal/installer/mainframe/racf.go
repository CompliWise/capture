package mainframe

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

type commandRunner interface {
	Run(name string, args ...string) ([]byte, error)
}

type defaultExecutor struct{}

func (defaultExecutor) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func resolveExecutor(opts installer.InstallOptions) commandRunner {
	if opts.Executor != nil {
		return opts.Executor
	}
	return defaultExecutor{}
}

// Installer implements mainframe_racf trust anchor installs on z/OS USS.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "mainframe_racf"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	if _, err := installer.ThumbprintFromPEM(opts.ChainPem); err != nil {
		return "", installer.NewCodedError("ERR_INVALID_PEM", "malformed certificate PEM")
	}

	racfProfile := strings.TrimSpace(opts.RacfProfile)
	if racfProfile == "" {
		return "", installer.NewCodedError(
			"ERR_INVALID_CONFIG",
			"racfProfile is required for mainframe_racf assignments",
		)
	}

	certPath := TempCertPath(opts.AssignmentID)
	if err := installer.AtomicWriteFile(certPath, opts.ChainPem, 0o600); err != nil {
		return "", err
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("staged PEM at %s", certPath))

	systemID := strings.TrimSpace(opts.SystemId)
	if opts.GatewayMode {
		if systemID != "" {
			logLines = append(
				logLines,
				fmt.Sprintf("gateway relay: staged PEM for system %s (SFTP+JCL push required)", systemID),
			)
		} else {
			logLines = append(logLines, "gateway relay: staged PEM for SFTP+JCL push")
		}
	} else {
		command := BuildTrustCommand(racfProfile, certPath)
		exec := resolveExecutor(opts)
		output, err := exec.Run("racf", command)
		logLines = append(logLines, fmt.Sprintf("racf %s", command))
		if len(output) > 0 {
			logLines = append(logLines, strings.TrimSpace(string(output)))
		}
		if err != nil {
			return strings.Join(logLines, "\n"), fmt.Errorf("racf trust install failed: %w", err)
		}
	}

	thumbprint := strings.TrimSpace(opts.Thumbprint)
	if thumbprint != "" {
		logLines = append(logLines, fmt.Sprintf("thumbprint=%s", thumbprint))
	}

	if opts.Metadata != nil {
		opts.Metadata.CertPath = certPath
		opts.Metadata.Thumbprint = thumbprint
		opts.Metadata.Alias = installer.DefaultAlias(opts.AssignmentID, opts.Alias)
		opts.Metadata.TrustStorePath = strings.TrimSpace(opts.TrustStorePath)
	}

	return strings.Join(logLines, "\n"), nil
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	racfProfile := strings.TrimSpace(record.Alias)
	if racfProfile == "" {
		racfProfile = strings.TrimSpace(record.TrustStorePath)
	}
	if racfProfile == "" {
		return "", fmt.Errorf("missing racf profile in install record")
	}

	certPath := strings.TrimSpace(record.CertPath)
	label := installer.DefaultAlias(record.AssignmentID, record.Alias)

	var logLines []string
	if certPath != "" {
		removeErr := os.Remove(certPath)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return "", fmt.Errorf("remove staged PEM: %w", removeErr)
		}
		if removeErr == nil {
			logLines = append(logLines, fmt.Sprintf("removed staged PEM %s", certPath))
		}
	}

	command := BuildDeleteCommand(racfProfile, label)
	exec := resolveExecutor(installer.InstallOptions{Executor: opts.Executor})
	output, err := exec.Run("racf", command)
	logLines = append(logLines, fmt.Sprintf("racf %s", command))
	if len(output) > 0 {
		logLines = append(logLines, strings.TrimSpace(string(output)))
	}
	if err != nil {
		return strings.Join(logLines, "\n"), fmt.Errorf("racf delete failed: %w", err)
	}

	return strings.Join(logLines, "\n"), nil
}
