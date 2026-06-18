package windows

import (
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

// DelegateTrustAnchor imports a trust anchor into LocalMachine\Root for dotnet OS-store delegation.
func DelegateTrustAnchor(opts installer.InstallOptions) (string, error) {
	delegated := opts
	if strings.TrimSpace(delegated.StoreLocation) == "" {
		delegated.StoreLocation = "LocalMachine"
	}
	if strings.TrimSpace(delegated.StoreName) == "" {
		delegated.StoreName = "Root"
	}
	log, err := installTrustAnchor(delegated, resolveExecutor(delegated))
	return SanitizeInstallerLog(log), err
}

// DelegateRemoveTrustAnchor removes a delegated trust anchor from the Windows certificate store.
func DelegateRemoveTrustAnchor(record installer.InstallRecord, exec installer.CommandExecutor) (string, error) {
	if exec == nil {
		exec = defaultExecutor{}
	}
	log, err := removeTrustAnchor(record, exec)
	return SanitizeInstallerLog(log), err
}
