package macos

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

var verifyRunner = defaultVerifyRunner

func defaultVerifyRunner(endpoint, serverName string) error {
	hostPort, sni, err := parseVerifyEndpoint(endpoint, serverName)
	if err != nil {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			fmt.Sprintf("post-install TLS verification failed: %v", err),
		)
	}

	path, err := exec.LookPath("openssl")
	if err != nil {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			"post-install TLS verification failed: openssl not found",
		)
	}

	args := []string{
		"s_client",
		"-connect", hostPort,
		"-brief",
	}
	if sni != "" {
		args = append(args, "-servername", sni)
	}

	cmd := exec.Command(path, args...)
	output, runErr := cmd.CombinedOutput()
	if runErr != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = runErr.Error()
		}
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			fmt.Sprintf("post-install TLS verification failed: %s", message),
		)
	}

	return nil
}

// VerifyTLS probes an HTTPS endpoint using system trust (macOS keychain).
func VerifyTLS(endpoint, serverName string) error {
	return verifyRunner(endpoint, serverName)
}

func parseVerifyEndpoint(endpoint, serverName string) (hostPort, sni string, err error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", "", fmt.Errorf("verify endpoint is empty")
	}

	parsed, parseErr := url.Parse(trimmed)
	if parseErr != nil {
		return "", "", fmt.Errorf("parse verify endpoint: %w", parseErr)
	}
	if parsed.Scheme != "https" {
		return "", "", fmt.Errorf("verify endpoint must use https")
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", "", fmt.Errorf("verify endpoint host is empty")
	}

	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	sni = strings.TrimSpace(serverName)
	if sni == "" {
		sni = host
	}

	if net.ParseIP(host) != nil {
		return net.JoinHostPort(host, port), "", nil
	}

	return net.JoinHostPort(host, port), sni, nil
}
