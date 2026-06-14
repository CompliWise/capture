package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

const defaultLinuxCAPath = "/usr/local/share/ca-certificates"

// Installer implements linux_update_ca_certificates for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" &&
		trustStoreType == "linux_update_ca_certificates"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	legacy := InstallOptions{
		CertFileName:   opts.CertFileName,
		TrustStorePath: opts.TrustStorePath,
		ReloadCommand:  opts.ReloadCommand,
		ChainPem:       opts.ChainPem,
		Thumbprint:     opts.Thumbprint,
	}
	return InstallLinuxUpdateCACertificates(legacy)
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	if strings.TrimSpace(record.CertPath) == "" {
		return "", fmt.Errorf("missing cert path in install record")
	}

	var logLines []string
	if err := os.Remove(record.CertPath); err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("remove certificate file: %w", err)
		}
		logLines = append(logLines, fmt.Sprintf("cert already absent: %s", record.CertPath))
	} else {
		logLines = append(logLines, fmt.Sprintf("removed %s", record.CertPath))
	}

	if usesSystemCAPath(filepath.Dir(record.CertPath)) {
		output, command, err := runCAUpdateCommand()
		logLines = append(logLines, fmt.Sprintf("%s %s", command, strings.TrimSpace(output)))
		if err != nil {
			return strings.Join(logLines, "\n"), err
		}
		return "update-ca-certificates: done\n" + strings.Join(logLines, "\n"), nil
	}

	return strings.Join(logLines, "\n"), nil
}

func usesSystemCAPath(storePath string) bool {
	cleaned := filepath.Clean(strings.TrimSpace(storePath))
	if cleaned == "" || cleaned == "." {
		return true
	}
	return cleaned == filepath.Clean(defaultLinuxCAPath)
}

// InstallOptions configures a Linux OS CA store install.
type InstallOptions struct {
	CertFileName   string
	TrustStorePath string
	ReloadCommand  []string
	ChainPem       string
	Thumbprint     string
}

// InstallLinuxUpdateCACertificates writes PEM material into the configured CA
// directory and runs update-ca-certificates (or update-ca-trust on RHEL).
func InstallLinuxUpdateCACertificates(opts InstallOptions) (string, error) {
	trimmed := strings.TrimSpace(opts.ChainPem)
	if trimmed == "" {
		return "", fmt.Errorf("certificate chain is empty")
	}

	storePath := strings.TrimSpace(opts.TrustStorePath)
	if storePath == "" {
		storePath = defaultLinuxCAPath
	}

	fileName := installer.SanitizeFileName(opts.CertFileName)
	destPath := filepath.Join(storePath, fileName)

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return "", fmt.Errorf("create ca-certificates directory: %w", err)
	}

	if existingThumbprint, err := fileThumbprint(destPath); err == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + destPath, nil
	}

	if err := os.WriteFile(destPath, []byte(trimmed+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write certificate file: %w", err)
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", destPath))

	if usesSystemCAPath(storePath) {
		output, command, err := runCAUpdateCommand()
		logLines = append(logLines, fmt.Sprintf("%s %s", command, strings.TrimSpace(output)))
		if err != nil {
			return strings.Join(logLines, "\n"), err
		}
	}

	if len(opts.ReloadCommand) > 0 {
		reloadOutput, reloadErr := runReloadCommand(opts.ReloadCommand)
		logLines = append(
			logLines,
			fmt.Sprintf("%s %s", strings.Join(opts.ReloadCommand, " "), strings.TrimSpace(reloadOutput)),
		)
		if reloadErr != nil {
			return strings.Join(logLines, "\n"), reloadErr
		}
	}

	return "update-ca-certificates: done\n" + strings.Join(logLines, "\n"), nil
}

func fileThumbprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return installer.ThumbprintFromPEM(string(data))
}

func runCAUpdateCommand() (string, string, error) {
	if path, err := exec.LookPath("/usr/sbin/update-ca-certificates"); err == nil {
		cmd := exec.Command(path)
		output, runErr := cmd.CombinedOutput()
		return string(output), path, runErr
	}

	if path, err := exec.LookPath("/usr/bin/update-ca-trust"); err == nil {
		cmd := exec.Command(path, "extract")
		output, runErr := cmd.CombinedOutput()
		return string(output), path + " extract", runErr
	}

	return "", "", fmt.Errorf("no supported CA update command found")
}

func runReloadCommand(command []string) (string, error) {
	if len(command) == 0 {
		return "", nil
	}

	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// CertPathForOptions returns the destination path for install state.
func CertPathForOptions(opts InstallOptions) string {
	storePath := strings.TrimSpace(opts.TrustStorePath)
	if storePath == "" {
		storePath = defaultLinuxCAPath
	}
	return filepath.Join(storePath, installer.SanitizeFileName(opts.CertFileName))
}
