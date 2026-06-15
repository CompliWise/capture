package windows

import (
	"fmt"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

func installTrustAnchor(opts installer.InstallOptions, exec installer.CommandExecutor) (string, error) {
	if err := ensurePlatform(opts); err != nil {
		return "", err
	}

	location, storeName := resolveStoreLocation(opts)
	storePath := certStorePath(location, storeName)

	tempPath, cleanup, err := writeTempFile("compliwise-trust", opts.ChainPem)
	if err != nil {
		return "", err
	}
	defer cleanup()

	escapedPath := strings.ReplaceAll(tempPath, "'", "''")
	script := fmt.Sprintf(
		`Import-Certificate -FilePath '%s' -CertStoreLocation '%s'`,
		escapedPath,
		storePath,
	)

	output, runErr := runPowerShell(exec, script)
	logLines := []string{
		fmt.Sprintf("Import-Certificate -CertStoreLocation %s", storePath),
		strings.TrimSpace(string(output)),
	}
	if runErr != nil {
		return strings.Join(logLines, "\n"), mapPowerShellError(output, runErr, "")
	}

	thumbprint := strings.TrimSpace(opts.Thumbprint)
	if thumbprint == "" {
		if computed, err := installer.ThumbprintFromPEM(opts.ChainPem); err == nil {
			thumbprint = computed
		}
	}

	logLines = append(logLines, fmt.Sprintf("thumbprint=%s store=%s", thumbprint, storeName))
	return strings.Join(logLines, "\n"), nil
}

func removeTrustAnchor(record installer.InstallRecord, exec installer.CommandExecutor) (string, error) {
	thumbprint := strings.TrimSpace(record.Thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint in install record")
	}

	storeName := strings.TrimSpace(record.StoreName)
	if storeName == "" {
		storeName = "Root"
	}

	storePath := certStorePath("LocalMachine", storeName)
	script := fmt.Sprintf(
		`Get-ChildItem '%s' | Where-Object { $_.Thumbprint -eq '%s' } | Remove-Item`,
		storePath,
		strings.ToUpper(thumbprint),
	)

	output, err := runPowerShell(exec, script)
	log := strings.TrimSpace(string(output))
	if err != nil {
		return log, mapPowerShellError(output, err, "")
	}

	return fmt.Sprintf("removed cert thumbprint=%s from %s\n%s", thumbprint, storePath, log), nil
}
