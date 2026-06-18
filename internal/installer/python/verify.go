package python

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

var verifyRunner = defaultVerifyRunner

func defaultVerifyRunner(endpoint string) error {
	python, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("python3 not found on PATH")
	}

	script := fmt.Sprintf(
		"import urllib.request; urllib.request.urlopen(%q)",
		strings.TrimSpace(endpoint),
	)
	cmd := exec.Command(python, "-c", script)
	if output, runErr := cmd.CombinedOutput(); runErr != nil {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			fmt.Sprintf("python HTTPS verification failed: %v", strings.TrimSpace(string(output))),
		)
	}
	return nil
}

// VerifyHTTPS runs a Python urllib probe against the endpoint.
func VerifyHTTPS(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	return verifyRunner(endpoint)
}
