package linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallLinuxUpdateCACertificatesWritesFile(t *testing.T) {
	if os.Getenv("RUN_LINUX_INSTALLER_INTEGRATION") != "1" {
		t.Skip("set RUN_LINUX_INSTALLER_INTEGRATION=1 to run integration test")
	}

	if _, err := exec.LookPath("/usr/sbin/update-ca-certificates"); err != nil {
		t.Skip("update-ca-certificates not available")
	}

	chainPem := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpEna4RqMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QgbG9jYWwwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAl0ZXN0IGxvY2FsMFwwDQYJKoZIhvcNAQEBBQADSwAwSAFBAKd8vG6k3Y1l
0n0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0
-----END CERTIFICATE-----`

	logOutput, err := InstallLinuxUpdateCACertificates(InstallOptions{
		CertFileName: "test.exapale.com.crt",
		ChainPem:     chainPem,
	})
	if err != nil {
		t.Fatalf("InstallLinuxUpdateCACertificates: %v\nlog: %s", err, logOutput)
	}

	destPath := filepath.Join(
		defaultLinuxCAPath,
		"test.exapale.com.crt",
	)
	if _, err := os.Stat(destPath); err != nil {
		t.Fatalf("expected certificate file at %s: %v", destPath, err)
	}

	if !strings.Contains(logOutput, "update-ca-certificates: done") {
		t.Fatalf("expected success log, got %q", logOutput)
	}
}

func TestSanitizeFileName(t *testing.T) {
	if got := sanitizeFileName("test.exapale.com.crt"); got != "test.exapale.com.crt" {
		t.Fatalf("expected test.exapale.com.crt, got %q", got)
	}
	if got := sanitizeFileName(""); got != "cert.crt" {
		t.Fatalf("expected cert.crt default, got %q", got)
	}
}
