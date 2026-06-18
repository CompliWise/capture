package dotnet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/linux"
	"github.com/compliwise/capture/internal/installer/windows"
)

// Installer implements dotnet_root_store for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "dotnet_root_store"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	if _, err := installer.ThumbprintFromPEM(opts.ChainPem); err != nil {
		return "", installer.NewCodedError("ERR_INVALID_PEM", "malformed certificate PEM")
	}

	if opts.PreferOsStore {
		return installPreferOsStore(opts)
	}

	bundlePath, err := ResolveBundlePath(opts.TrustStorePath)
	if err != nil {
		return "", err
	}

	if existingThumbprint, readErr := fileThumbprint(bundlePath); readErr == nil &&
		existingThumbprint == strings.TrimSpace(opts.Thumbprint) &&
		opts.Thumbprint != "" {
		return "idempotent: thumbprint unchanged at " + bundlePath, nil
	}

	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	if err := installer.AtomicWriteFile(bundlePath, opts.ChainPem, 0o644); err != nil {
		return "", err
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", bundlePath))
	if opts.Thumbprint != "" {
		logLines = append(logLines, fmt.Sprintf("thumbprint=%s", strings.TrimSpace(opts.Thumbprint)))
	}

	if envPath := strings.TrimSpace(opts.EnvFilePath); envPath != "" {
		if err := upsertEnvLine(envPath, dotnetCAEnvKey, bundlePath); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, fmt.Sprintf("updated %s", envPath))
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
		if verifyErr := VerifyTLS(endpoint, bundlePath, opts.VerifyServerName); verifyErr != nil {
			return strings.Join(logLines, "\n"), verifyErr
		}
		logLines = append(logLines, "dotnet TLS verification succeeded")
	}

	if opts.Metadata != nil {
		opts.Metadata.CertPath = bundlePath
		opts.Metadata.TrustStorePath = bundlePath
		opts.Metadata.EnvFilePath = strings.TrimSpace(opts.EnvFilePath)
		opts.Metadata.PreferOsStore = false
	}

	return strings.Join(logLines, "\n"), nil
}

func installPreferOsStore(opts installer.InstallOptions) (string, error) {
	if runtime.GOOS == "windows" || opts.Executor != nil {
		log, err := windows.DelegateTrustAnchor(opts)
		if err != nil {
			return log, err
		}
		if opts.Metadata != nil {
			storeName := strings.TrimSpace(opts.StoreName)
			if storeName == "" {
				storeName = "Root"
			}
			thumbprint := strings.TrimSpace(opts.Thumbprint)
			opts.Metadata.PreferOsStore = true
			opts.Metadata.StoreName = storeName
			opts.Metadata.CertPath = fmt.Sprintf(`Cert:\LocalMachine\%s\%s`, storeName, strings.ToUpper(thumbprint))
			opts.Metadata.Thumbprint = thumbprint
		}
		return log, nil
	}

	linuxOpts := linux.InstallOptions{
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
	log, err := linux.InstallLinuxUpdateCACertificates(linuxOpts)
	if err != nil {
		return log, err
	}

	if opts.Metadata != nil {
		certPath := linux.CertPathForOptions(linuxOpts)
		opts.Metadata.PreferOsStore = true
		opts.Metadata.CertPath = certPath
		opts.Metadata.TrustStorePath = strings.TrimSpace(opts.TrustStorePath)
		opts.Metadata.Thumbprint = strings.TrimSpace(opts.Thumbprint)
	}

	return log, nil
}

func (i *Installer) Remove(ctx context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	if record.PreferOsStore {
		return removePreferOsStore(ctx, record)
	}

	bundlePath := strings.TrimSpace(record.CertPath)
	if bundlePath == "" {
		return "", fmt.Errorf("missing bundle path in install record")
	}

	var logLines []string
	if err := os.Remove(bundlePath); err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("remove bundle file: %w", err)
		}
		logLines = append(logLines, "bundle already absent")
	} else {
		logLines = append(logLines, fmt.Sprintf("removed %s", bundlePath))
	}

	if envPath := strings.TrimSpace(record.EnvFilePath); envPath != "" {
		if err := removeEnvLine(envPath, dotnetCAEnvKey); err != nil {
			return strings.Join(logLines, "\n"), err
		}
		logLines = append(logLines, fmt.Sprintf("cleared %s from %s", dotnetCAEnvKey, envPath))
	}

	return strings.Join(logLines, "\n"), nil
}

func removePreferOsStore(ctx context.Context, record installer.InstallRecord) (string, error) {
	if runtime.GOOS == "windows" || strings.HasPrefix(record.CertPath, `Cert:\`) {
		return windows.DelegateRemoveTrustAnchor(record, nil)
	}

	linuxInst := linux.Installer{}
	return linuxInst.Remove(ctx, installer.RemoveOptions{
		AssignmentID:   record.AssignmentID,
		TrustStoreType: "linux_update_ca_certificates",
		Record:         record,
	})
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
