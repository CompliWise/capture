package windows

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/bluewave-labs/capture/internal/installer"
)

func installIISIdentity(
	opts installer.InstallOptions,
	exec installer.CommandExecutor,
) (string, installer.InstallRecord, error) {
	record := installer.InstallRecord{}

	if err := ensurePlatform(opts); err != nil {
		return "", record, err
	}

	if strings.TrimSpace(opts.PrivateKeyPem) == "" {
		return "", record, fmt.Errorf("private key is required for server_identity")
	}

	if err := installer.ValidateKeyMatchesCert(opts.ChainPem, opts.PrivateKeyPem); err != nil {
		return "", record, err
	}

	iis := resolveIISDefaults(opts.IIS)
	siteName := iis.SiteName

	certPath, certCleanup, err := writeTempFile("compliwise-cert", opts.ChainPem)
	if err != nil {
		return "", record, err
	}
	defer certCleanup()

	keyPath, keyCleanup, err := writeTempFile("compliwise-key", opts.PrivateKeyPem)
	if err != nil {
		return "", record, err
	}
	defer keyCleanup()

	location, storeName := resolveStoreLocation(opts)
	storePath := certStorePath(location, storeName)
	escapedCert := strings.ReplaceAll(certPath, "'", "''")
	escapedKey := strings.ReplaceAll(keyPath, "'", "''")

	importScript := fmt.Sprintf(
		`$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile('%s','%s'); `+
			`$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('%s','%s'); `+
			`$store.Open('ReadWrite'); $store.Add($cert); $store.Close()`,
		escapedCert,
		escapedKey,
		storeName,
		location,
	)
	importOutput, importErr := runPowerShell(exec, importScript)
	logLines := []string{
		fmt.Sprintf("CreateFromPemFile -CertStoreLocation %s", storePath),
		strings.TrimSpace(string(importOutput)),
	}
	if importErr != nil {
		return strings.Join(logLines, "\n"), record, mapPowerShellError(importOutput, importErr, siteName)
	}

	thumbprint := strings.TrimSpace(opts.Thumbprint)
	if thumbprint == "" {
		if computed, err := installer.ThumbprintFromPEM(opts.ChainPem); err == nil {
			thumbprint = computed
		}
	}

	bindingPath := sslBindingPath(iis)
	snapshotScript := fmt.Sprintf(
		`Import-Module WebAdministration; (Get-Item '%s').Thumbprint`,
		bindingPath,
	)
	snapshotOutput, snapshotErr := runPowerShell(exec, snapshotScript)
	snapshotThumbprint := strings.TrimSpace(string(snapshotOutput))
	logLines = append(logLines, fmt.Sprintf("snapshot binding %s thumbprint=%s", bindingPath, snapshotThumbprint))
	if snapshotErr != nil {
		return strings.Join(logLines, "\n"), record, mapPowerShellError(snapshotOutput, snapshotErr, siteName)
	}

	updateScript := buildBindingUpdateScript(iis, thumbprint, siteName)
	updateOutput, updateErr := runPowerShell(exec, updateScript)
	logLines = append(logLines, strings.TrimSpace(string(updateOutput)))
	if updateErr != nil {
		return strings.Join(logLines, "\n"), record, mapPowerShellError(updateOutput, updateErr, siteName)
	}

	if endpoint := strings.TrimSpace(opts.VerifyEndpoint); endpoint != "" {
		if verifyErr := verifyEndpointThumbprint(endpoint, thumbprint); verifyErr != nil {
			logLines = append(logLines, verifyErr.Error())
			return strings.Join(logLines, "\n"), record, verifyErr
		}
		logLines = append(logLines, fmt.Sprintf("verified thumbprint at %s", endpoint))
	}

	record = installer.InstallRecord{
		Thumbprint:                thumbprint,
		StoreName:                 storeName,
		BindingSnapshotThumbprint: snapshotThumbprint,
		IISSiteName:               siteName,
		IISBindingHost:            strings.TrimSpace(iis.BindingHost),
		IISBindingPort:            iis.BindingPort,
		CertPath:                  fmt.Sprintf(`%s\%s`, storePath, strings.ToUpper(thumbprint)),
	}
	if opts.Metadata != nil {
		*opts.Metadata = record
	}

	return strings.Join(logLines, "\n"), record, nil
}

func buildBindingUpdateScript(iis installer.IISConfig, thumbprint, siteName string) string {
	iis = resolveIISDefaults(iis)
	bindingPath := sslBindingPath(iis)
	hostHeader := strings.TrimSpace(iis.BindingHost)
	sslFlags := 0
	if iis.SNI && hostHeader != "" {
		sslFlags = 1
	}

	parts := []string{
		"Import-Module WebAdministration",
		fmt.Sprintf(`$site = '%s'`, strings.ReplaceAll(siteName, "'", "''")),
		fmt.Sprintf(`$thumb = '%s'`, strings.ToUpper(thumbprint)),
	}

	if hostHeader != "" {
		parts = append(parts,
			fmt.Sprintf(`New-WebBinding -Name $site -Protocol https -Port %d -HostHeader '%s' -SslFlags %d -ErrorAction SilentlyContinue`,
				iis.BindingPort,
				strings.ReplaceAll(hostHeader, "'", "''"),
				sslFlags,
			),
		)
	}

	parts = append(parts,
		fmt.Sprintf(`Set-ItemProperty '%s' -Name Thumbprint -Value $thumb`, bindingPath),
	)

	return strings.Join(parts, "; ")
}

func removeIISIdentity(record installer.InstallRecord, exec installer.CommandExecutor) (string, error) {
	thumbprint := strings.TrimSpace(record.Thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint in install record")
	}

	iis := resolveIISDefaults(installer.IISConfig{
		SiteName:    record.IISSiteName,
		BindingHost: record.IISBindingHost,
		BindingPort: record.IISBindingPort,
		IPAddress:   "*",
		SNI:         record.IISBindingHost != "",
	})

	var logLines []string

	if snapshot := strings.TrimSpace(record.BindingSnapshotThumbprint); snapshot != "" {
		restoreScript := fmt.Sprintf(
			`Import-Module WebAdministration; Set-ItemProperty '%s' -Name Thumbprint -Value '%s'`,
			sslBindingPath(iis),
			strings.ToUpper(snapshot),
		)
		output, err := runPowerShell(exec, restoreScript)
		logLines = append(logLines, strings.TrimSpace(string(output)))
		if err != nil {
			return strings.Join(logLines, "\n"), mapPowerShellError(output, err, iis.SiteName)
		}
		logLines = append(logLines, fmt.Sprintf("restored binding thumbprint=%s", snapshot))
	}

	storeName := strings.TrimSpace(record.StoreName)
	if storeName == "" {
		storeName = "My"
	}

	removeScript := fmt.Sprintf(
		`Get-ChildItem '%s' | Where-Object { $_.Thumbprint -eq '%s' } | Remove-Item`,
		certStorePath("LocalMachine", storeName),
		strings.ToUpper(thumbprint),
	)
	output, err := runPowerShell(exec, removeScript)
	logLines = append(logLines, strings.TrimSpace(string(output)))
	if err != nil {
		return strings.Join(logLines, "\n"), mapPowerShellError(output, err, iis.SiteName)
	}

	return strings.Join(logLines, "\n"), nil
}

func verifyEndpointThumbprint(endpoint, expectedThumbprint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			"Post-install TLS verification failed: invalid verify endpoint",
		)
	}

	host := parsed.Host
	if host == "" {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			"Post-install TLS verification failed: invalid verify endpoint",
		)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(
		dialer,
		"tcp",
		host,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	)
	if err != nil {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			fmt.Sprintf("Post-install TLS verification failed: %v", err),
		)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			"Post-install TLS verification failed: no peer certificate",
		)
	}

	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	actual := strings.ToLower(hex.EncodeToString(sum[:]))
	expected := strings.ToLower(strings.TrimSpace(expectedThumbprint))
	if actual != expected {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			"Post-install TLS verification failed: thumbprint mismatch",
		)
	}

	return nil
}
