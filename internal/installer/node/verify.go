package node

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

var verifyRunner = defaultVerifyRunner

func defaultVerifyRunner(endpoint string) error {
	nodeBinary, err := exec.LookPath("node")
	if err != nil {
		return fmt.Errorf("node not found on PATH")
	}

	script := fmt.Sprintf(
		"require('https').get(%q, r => process.exit(r.statusCode===200?0:1))",
		strings.TrimSpace(endpoint),
	)
	cmd := exec.Command(nodeBinary, "-e", script)
	if output, runErr := cmd.CombinedOutput(); runErr != nil {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			fmt.Sprintf("node HTTPS verification failed: %v", strings.TrimSpace(string(output))),
		)
	}
	return nil
}

// VerifyHTTPS runs a Node https.get probe against the endpoint.
func VerifyHTTPS(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	return verifyRunner(endpoint)
}
