package dotnet

import (
	"strings"

	"github.com/bluewave-labs/capture/internal/installer/linux"
)

var verifyRunner = defaultVerifyRunner

func defaultVerifyRunner(endpoint, bundlePath, serverName string) error {
	return linux.VerifyTLS(endpoint, bundlePath, serverName)
}

// VerifyTLS probes an HTTPS endpoint using the custom CA bundle file.
func VerifyTLS(endpoint, bundlePath, serverName string) error {
	if strings.TrimSpace(endpoint) == "" {
		return nil
	}
	return verifyRunner(endpoint, bundlePath, serverName)
}
