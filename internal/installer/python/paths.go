package python

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var certifiRunner = defaultCertifiRunner

func defaultCertifiRunner(python string) (string, error) {
	cmd := exec.Command(python, "-m", "certifi")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve certifi bundle: %w", err)
	}
	path := strings.TrimSpace(string(output))
	if path == "" {
		return "", fmt.Errorf("certifi bundle path is empty")
	}
	return path, nil
}

// ResolveBundlePath resolves the certifi cacert.pem target path.
func ResolveBundlePath(trustStorePath, pythonVenvPath string) (string, error) {
	if trimmed := strings.TrimSpace(trustStorePath); trimmed != "" {
		return trimmed, nil
	}

	if trimmed := strings.TrimSpace(pythonVenvPath); trimmed != "" {
		return CertifiPathFromVenv(trimmed)
	}

	return systemCertifiPath()
}

// CertifiPathFromVenv resolves certifi bundle path inside a Python virtualenv.
func CertifiPathFromVenv(venvPath string) (string, error) {
	venv := strings.TrimSpace(venvPath)
	if venv == "" {
		return "", fmt.Errorf("pythonVenvPath is empty")
	}

	venvPython := filepath.Join(venv, "bin", "python")
	if _, err := os.Stat(venvPython); err == nil {
		return certifiRunner(venvPython)
	}

	matches, err := filepath.Glob(
		filepath.Join(venv, "lib", "python*", "site-packages", "certifi", "cacert.pem"),
	)
	if err != nil {
		return "", fmt.Errorf("glob venv certifi path: %w", err)
	}
	for _, match := range matches {
		if _, statErr := os.Stat(match); statErr == nil {
			return match, nil
		}
	}

	return "", fmt.Errorf("certifi bundle not found in venv %s", venv)
}

func systemCertifiPath() (string, error) {
	python, err := exec.LookPath("python3")
	if err != nil {
		return "", fmt.Errorf("python3 not found on PATH")
	}
	return certifiRunner(python)
}
