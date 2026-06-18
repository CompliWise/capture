package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/testfixtures"
)

func TestPythonInstallerAppendAndRemove(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.pem")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-py",
		TrustStoreType: "python_certifi_bundle",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		Alias:          "test-alias",
		TrustStorePath: bundlePath,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if !strings.Contains(string(data), thumbprint) {
		t.Fatal("expected thumbprint marker in bundle")
	}

	_, err = inst.Remove(t.Context(), installer.RemoveOptions{
		AssignmentID:   "assign-py",
		TrustStoreType: "python_certifi_bundle",
		Record: installer.InstallRecord{
			AssignmentID: "assign-py",
			Alias:        "test-alias",
			CertPath:     bundlePath,
		},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	data, err = os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle after remove: %v", err)
	}
	if strings.Contains(string(data), "compliwise-test-alias-start") {
		t.Fatal("expected marker block removed")
	}
}

func TestPythonInstallerRejectsMalformedPEM(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.pem")
	inst := Installer{}

	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-py",
		TrustStoreType: "python_certifi_bundle",
		MaterialType:   "trust_anchor",
		ChainPem:       "not-a-pem",
		Thumbprint:     "abc",
		TrustStorePath: bundlePath,
	})
	if err == nil {
		t.Fatal("expected malformed PEM error")
	}
	if installer.ErrorCode(err) != "ERR_INVALID_PEM" {
		t.Fatalf("expected ERR_INVALID_PEM, got %q", installer.ErrorCode(err))
	}
}

func TestPythonInstallerIdempotentThumbprint(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.pem")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	opts := installer.InstallOptions{
		AssignmentID:   "assign-py",
		TrustStoreType: "python_certifi_bundle",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		Alias:          "dup",
		TrustStorePath: bundlePath,
	}

	firstLog, err := inst.Install(t.Context(), opts)
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	secondLog, err := inst.Install(t.Context(), opts)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(secondLog, "idempotent") {
		t.Fatalf("expected idempotent log, got %q", secondLog)
	}
	if firstLog == secondLog && strings.Contains(firstLog, "idempotent") {
		t.Fatal("first install should not be idempotent")
	}

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if strings.Count(string(data), "compliwise-dup-start") != 1 {
		t.Fatal("expected single marker block")
	}
}

func TestPythonInstallerEnvFileExport(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.pem")
	envPath := filepath.Join(dir, "requests_ca_bundle")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-py",
		TrustStoreType: "python_certifi_bundle",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: bundlePath,
		EnvFilePath:    envPath,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	expected := "export REQUESTS_CA_BUNDLE=" + bundlePath
	if !strings.Contains(string(envData), expected) {
		t.Fatalf("expected %q in env file, got %q", expected, string(envData))
	}
}

func TestPythonInstallerRemoveClearsEnv(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.pem")
	envPath := filepath.Join(dir, "requests_ca_bundle")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-py",
		TrustStoreType: "python_certifi_bundle",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		Alias:          "env-clear",
		TrustStorePath: bundlePath,
		EnvFilePath:    envPath,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	_, err = inst.Remove(t.Context(), installer.RemoveOptions{
		AssignmentID:   "assign-py",
		TrustStoreType: "python_certifi_bundle",
		Record: installer.InstallRecord{
			AssignmentID: "assign-py",
			Alias:        "env-clear",
			CertPath:     bundlePath,
			EnvFilePath:  envPath,
		},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		envData, readErr := os.ReadFile(envPath)
		if readErr == nil && strings.Contains(string(envData), "REQUESTS_CA_BUNDLE") {
			t.Fatal("expected env export removed")
		}
	}
}
