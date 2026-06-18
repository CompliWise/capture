package windows

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

func ensurePlatform(opts installer.InstallOptions) error {
	if opts.Executor != nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return installer.NewCodedError(
			"ERR_PLATFORM_MISMATCH",
			"Windows certificate store installers require a Windows agent host",
		)
	}
	return nil
}

func resolveStoreLocation(opts installer.InstallOptions) (location, name string) {
	location = strings.TrimSpace(opts.StoreLocation)
	if location == "" {
		location = "LocalMachine"
	}

	name = strings.TrimSpace(opts.StoreName)
	if name == "" {
		if opts.MaterialType == "server_identity" {
			name = "My"
		} else {
			name = "Root"
		}
	}

	return location, name
}

func certStorePath(location, name string) string {
	return fmt.Sprintf(`Cert:\%s\%s`, location, name)
}

func runPowerShell(exec installer.CommandExecutor, script string) ([]byte, error) {
	return exec.Run(
		"powershell",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	)
}

func writeTempFile(prefix, content string) (path string, cleanup func(), err error) {
	file, err := os.CreateTemp("", prefix+"-*.pem")
	if err != nil {
		return "", nil, fmt.Errorf("create temp file: %w", err)
	}

	path = file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err := file.WriteString(strings.TrimSpace(content) + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("write temp file: %w", err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, fmt.Errorf("close temp file: %w", err)
	}

	return path, func() { _ = os.Remove(path) }, nil
}

func mapPowerShellError(output []byte, err error, siteName string) error {
	if err == nil {
		return nil
	}

	combined := strings.ToLower(string(output) + " " + err.Error())
	switch {
	case strings.Contains(combined, "access is denied") || strings.Contains(combined, "access denied"):
		return installer.NewCodedError(
			"ERR_PERMISSION",
			"Insufficient privileges to modify certificate store or IIS configuration. Run the agent as Local System or grant gMSA rights per operations guide.",
		)
	case strings.Contains(combined, "cannot find path"),
		strings.Contains(combined, "site not found"),
		strings.Contains(combined, "does not exist") && strings.Contains(combined, "site"):
		if siteName != "" {
			return installer.NewCodedError(
				"ERR_IIS_SITE_NOT_FOUND",
				fmt.Sprintf("IIS site not found: %s", siteName),
			)
		}
	case strings.Contains(combined, "already exists") || strings.Contains(combined, "binding conflict"):
		return installer.NewCodedError(
			"ERR_BINDING_CONFLICT",
			"HTTPS binding conflict for the configured host and port",
		)
	}

	return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
}

func resolveIISDefaults(cfg installer.IISConfig) installer.IISConfig {
	resolved := cfg
	if strings.TrimSpace(resolved.SiteName) == "" {
		resolved.SiteName = "Default Web Site"
	}
	if resolved.BindingPort <= 0 {
		resolved.BindingPort = 443
	}
	if strings.TrimSpace(resolved.IPAddress) == "" {
		resolved.IPAddress = "*"
	}
	return resolved
}

func sslBindingAddress(ip string) string {
	if strings.TrimSpace(ip) == "" || ip == "*" {
		return "0.0.0.0"
	}
	return ip
}

func sslBindingPath(cfg installer.IISConfig) string {
	cfg = resolveIISDefaults(cfg)
	host := strings.TrimSpace(cfg.BindingHost)
	if host == "" {
		return fmt.Sprintf(
			`IIS:\SslBindings\%s!%d`,
			sslBindingAddress(cfg.IPAddress),
			cfg.BindingPort,
		)
	}
	return fmt.Sprintf(
		`IIS:\SslBindings\%s!%d!%s`,
		sslBindingAddress(cfg.IPAddress),
		cfg.BindingPort,
		host,
	)
}
