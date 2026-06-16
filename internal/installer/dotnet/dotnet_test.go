package dotnet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/testfixtures"
)

type mockCommandExecutor struct {
	calls []string
}

func (m *mockCommandExecutor) Run(name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	m.calls = append(m.calls, call)
	return []byte("OK"), nil
}

func TestDotnetInstallerWritesBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trust.pem")
	envPath := filepath.Join(dir, "dotnet.env")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	originalVerify := verifyRunner
	t.Cleanup(func() { verifyRunner = originalVerify })
	verifyRunner = func(_, _, _ string) error { return nil }

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-dotnet",
		TrustStoreType: "dotnet_root_store",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: bundlePath,
		EnvFilePath:    envPath,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("expected bundle file: %v", err)
	}

	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	if !strings.Contains(string(envData), dotnetCAEnvKey+"="+bundlePath) {
		t.Fatalf("expected %s in env file", dotnetCAEnvKey)
	}
}

func TestDotnetInstallerRejectsMalformedPEM(t *testing.T) {
	inst := Installer{}
	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-dotnet",
		TrustStoreType: "dotnet_root_store",
		MaterialType:   "trust_anchor",
		ChainPem:       "not-a-pem",
		TrustStorePath: filepath.Join(t.TempDir(), "trust.pem"),
	})
	if err == nil {
		t.Fatal("expected malformed PEM rejection")
	}
	if installer.ErrorCode(err) != "ERR_INVALID_PEM" {
		t.Fatalf("expected ERR_INVALID_PEM, got %q", installer.ErrorCode(err))
	}
}

func TestDotnetInstallerIdempotentThumbprint(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trust.pem")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	opts := installer.InstallOptions{
		AssignmentID:   "assign-dotnet",
		TrustStoreType: "dotnet_root_store",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: bundlePath,
	}

	if _, err := inst.Install(t.Context(), opts); err != nil {
		t.Fatalf("first install: %v", err)
	}

	log, err := inst.Install(t.Context(), opts)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(log, "idempotent") {
		t.Fatalf("expected idempotent log, got %q", log)
	}
}

func TestDotnetInstallerEnvUpsert(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "trust.pem")
	envPath := filepath.Join(dir, "dotnet.env")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-dotnet",
		TrustStoreType: "dotnet_root_store",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: bundlePath,
		EnvFilePath:    envPath,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	if _, err := os.Stat(envPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("expected env temp file to be renamed away")
	}

	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	if !strings.Contains(string(envData), dotnetCAEnvKey+"=") {
		t.Fatalf("expected %s assignment in env file", dotnetCAEnvKey)
	}
}

func TestDotnetInstallerPreferOsStoreLinux(t *testing.T) {
	_ = os.Setenv("COMPLIWISE_SKIP_CA_UPDATE", "1")
	t.Cleanup(func() { _ = os.Unsetenv("COMPLIWISE_SKIP_CA_UPDATE") })

	dir := t.TempDir()
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	metadata := &installer.InstallRecord{}
	log, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-dotnet",
		TrustStoreType: "dotnet_root_store",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: dir,
		Alias:          "dotnet-ca",
		PreferOsStore:  true,
		Metadata:       metadata,
	})
	if err != nil {
		t.Fatalf("install: %v\nlog: %s", err, log)
	}
	if !metadata.PreferOsStore {
		t.Fatal("expected PreferOsStore metadata")
	}
	if metadata.CertPath == "" {
		t.Fatal("expected cert path in metadata")
	}
}

func TestDotnetInstallerPreferOsStoreWindowsWithExecutor(t *testing.T) {
	executor := &mockCommandExecutor{}
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	metadata := &installer.InstallRecord{}
	log, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-dotnet",
		TrustStoreType: "dotnet_root_store",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		PreferOsStore:  true,
		Executor:       executor,
		Metadata:       metadata,
	})
	if err != nil {
		t.Fatalf("install: %v\nlog: %s", err, log)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 powershell call, got %d", len(executor.calls))
	}
	if !strings.Contains(executor.calls[0], "Import-Certificate") {
		t.Fatalf("expected Import-Certificate in %q", executor.calls[0])
	}
	if !metadata.PreferOsStore {
		t.Fatal("expected PreferOsStore metadata")
	}
	if !strings.HasPrefix(metadata.CertPath, `Cert:\LocalMachine\Root\`) {
		t.Fatalf("unexpected cert path %q", metadata.CertPath)
	}
}
