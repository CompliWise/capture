package linux

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const defaultLinuxCAPath = "/usr/local/share/ca-certificates"

var safeNamePattern = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// InstallOptions configures a Linux OS CA store install.
type InstallOptions struct {
	CertFileName   string
	TrustStorePath string
	ReloadCommand  []string
	ChainPem       string
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

	fileName := sanitizeFileName(opts.CertFileName)
	destPath := filepath.Join(storePath, fileName)

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return "", fmt.Errorf("create ca-certificates directory: %w", err)
	}

	if err := os.WriteFile(destPath, []byte(trimmed+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write certificate file: %w", err)
	}

	var logLines []string
	logLines = append(logLines, fmt.Sprintf("wrote %s", destPath))

	output, command, err := runCAUpdateCommand()
	logLines = append(logLines, fmt.Sprintf("%s %s", command, strings.TrimSpace(output)))
	if err != nil {
		return strings.Join(logLines, "\n"), err
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

func sanitizeFileName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "cert.crt"
	}
	return safeNamePattern.ReplaceAllString(trimmed, "-")
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
