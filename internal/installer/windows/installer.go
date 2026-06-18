package windows

import (
	"context"

	"github.com/compliwise/capture/internal/installer"
)

// Installer implements windows_cert_store for trust anchors and IIS server identity.
type Installer struct{}

func (Installer) Supports(materialType, trustStoreType string) bool {
	if trustStoreType != "windows_cert_store" {
		return false
	}
	return materialType == "trust_anchor" || materialType == "server_identity"
}

func (Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	exec := resolveExecutor(opts)

	switch opts.MaterialType {
	case "server_identity":
		log, record, err := installIISIdentity(opts, exec)
		if opts.Metadata != nil {
			*opts.Metadata = record
		}
		return SanitizeInstallerLog(log), err
	default:
		log, err := installTrustAnchor(opts, exec)
		return SanitizeInstallerLog(log), err
	}
}

func (Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	exec := defaultExecutor{}

	switch {
	case opts.Record.IISSiteName != "" || opts.Record.BindingSnapshotThumbprint != "":
		log, err := removeIISIdentity(opts.Record, exec)
		return SanitizeInstallerLog(log), err
	default:
		log, err := removeTrustAnchor(opts.Record, exec)
		return SanitizeInstallerLog(log), err
	}
}

// InstallWithRecord runs server identity install and returns rollback metadata.
func InstallWithRecord(opts installer.InstallOptions) (string, installer.InstallRecord, error) {
	log, record, err := installIISIdentity(opts, resolveExecutor(opts))
	return SanitizeInstallerLog(log), record, err
}
