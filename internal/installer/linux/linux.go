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
		AssignmentID:     opts.AssignmentID,
		CertFileName:     opts.CertFileName,
		TrustStorePath:   opts.TrustStorePath,
		ReloadCommand:    opts.ReloadCommand,
		ChainPem:         opts.ChainPem,
		Thumbprint:       opts.Thumbprint,
		Alias:            opts.Alias,
		VerifyEndpoint:   opts.VerifyEndpoint,
		VerifyServerName: opts.VerifyServerName,
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

	if shouldRunCAUpdate() {
		output, command, err := runUpdateCommands(UpdateCommandsForCertPath(record.CertPath))
		logLines = append(logLines, fmt.Sprintf("%s %s", command, strings.TrimSpace(output)))
		if err != nil {
			return strings.Join(logLines, "\n"), err
		}
		return "update-ca-certificates: done\n" + strings.Join(logLines, "\n"), nil
	}

	return strings.Join(logLines, "\n"), nil
}

// InstallOptions configures a Linux OS CA store install.
type InstallOptions struct {
	AssignmentID     string
	CertFileName     string
	TrustStorePath   string
	ReloadCommand    []string
	ChainPem         string
	Thumbprint       string
	Alias            string
	VerifyEndpoint   string
	VerifyServerName string
}

// InstallLinuxUpdateCACertificates writes PEM material into the configured CA
// directory and runs the distro-appropriate trust refresh command.
func InstallLinuxUpdateCACertificates(opts InstallOptions) (string, error) {
	trimmed := strings.TrimSpace(opts.ChainPem)
	if trimmed == "" {
		return "", fmt.Errorf("certificate chain is empty")
	}

	storePath, fileName, profile := resolveInstallTarget(opts)
	destPath := filepath.Join(storePath, fileName)

	if err := rejectTraversalInInputs(opts); err != nil {
		return "", err
	}

	if err := installer.ValidatePathWithinBase(storePath, destPath); err != nil {
		return "", err
	}

	if existingThumbprint, err := fileThumbprint(destPath); err == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + destPath, nil
	}

	if err := os.MkdirAll(storePath, 0o755); err != nil {
		return "", fmt.Errorf("create ca-certificates directory: %w", err)
	}

	if err := os.WriteFile(destPath, []byte(trimmed+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write certificate file: %w", err)
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", destPath))

	if shouldRunCAUpdate() {
		output, command, err := runProfileUpdate(profile)
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

	if endpoint := strings.TrimSpace(opts.VerifyEndpoint); endpoint != "" {
		if verifyErr := VerifyTLS(endpoint, profile.BundlePath, opts.VerifyServerName); verifyErr != nil {
			logLines = append(logLines, verifyErr.Error())
			return strings.Join(logLines, "\n"), verifyErr
		}
		logLines = append(logLines, fmt.Sprintf("verified endpoint %s", endpoint))
	}

	return "update-ca-certificates: done\n" + strings.Join(logLines, "\n"), nil
}

func resolveInstallTarget(opts InstallOptions) (storePath, fileName string, profile DistroProfile) {
	configuredPath := strings.TrimSpace(opts.TrustStorePath)
	if configuredPath != "" {
		profile = ProfileFromPath(configuredPath)
		return configuredPath, resolveCertFileName(opts, profile.FileExt), profile
	}

	kind, err := DetectDistro(defaultOSReleasePath)
	if err != nil {
		kind = DistroDebian
	}
	profile = ProfileFor(kind)
	return profile.InstallDir, resolveCertFileName(opts, profile.FileExt), profile
}

func rejectTraversalInInputs(opts InstallOptions) error {
	for _, value := range []string{
		opts.TrustStorePath,
		opts.CertFileName,
		opts.Alias,
	} {
		if strings.Contains(strings.TrimSpace(value), "..") {
			return fmt.Errorf("path traversal is not allowed")
		}
	}
	return nil
}

func resolveCertFileName(opts InstallOptions, ext string) string {
	configured := strings.TrimSpace(opts.CertFileName)
	if configured != "" && configured != "tls.crt" {
		return installer.SanitizeFileName(configured)
	}

	alias := installer.DefaultAlias(opts.AssignmentID, opts.Alias)
	baseName := "compliwise-" + alias
	if !strings.HasSuffix(baseName, ext) {
		baseName += ext
	}
	return installer.SanitizeFileName(baseName)
}

func shouldRunCAUpdate() bool {
	return strings.TrimSpace(os.Getenv("COMPLIWISE_SKIP_CA_UPDATE")) != "1"
}

func runProfileUpdate(profile DistroProfile) (string, string, error) {
	return runUpdateCommands(profile.UpdateCommands)
}

func runUpdateCommands(commands [][]string) (string, string, error) {
	for _, command := range commands {
		if len(command) == 0 {
			continue
		}

		binary, err := resolveCommandBinary(command[0])
		if err != nil {
			continue
		}

		cmd := exec.Command(binary, command[1:]...)
		output, runErr := cmd.CombinedOutput()
		if runErr == nil {
			label := strings.Join(command, " ")
			return string(output), label, nil
		}
	}

	return "", "", fmt.Errorf("no supported CA update command found")
}

func resolveCommandBinary(name string) (string, error) {
	candidates := []string{
		filepath.Join("/usr/sbin", name),
		filepath.Join("/usr/bin", name),
		name,
	}
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("command not found: %s", name)
}

func fileThumbprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return installer.ThumbprintFromPEM(string(data))
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
	storePath, fileName, _ := resolveInstallTarget(opts)
	return filepath.Join(storePath, fileName)
}
