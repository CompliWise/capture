package database

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/testfixtures"
)

type mockCommandExecutor struct {
	calls []string
}

func (m *mockCommandExecutor) Run(name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	m.calls = append(m.calls, call)
	return []byte("OK"), nil
}

func TestPostgreSQLWritesRootCrt(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, ".postgresql", "root.crt")
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}

	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	originalVerify := verifyRunner
	t.Cleanup(func() { verifyRunner = originalVerify })
	verifyRunner = func(_, _, _ string) error { return nil }

	metadata := &installer.InstallRecord{}
	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-pg",
		TrustStoreType: "postgresql_ssl_root",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: targetPath,
		DBUser:         currentUser.Username,
		Metadata:       metadata,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("stat root.crt: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read root.crt: %v", err)
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatal("expected PEM content in root.crt")
	}
	if metadata.CertPath != targetPath {
		t.Fatalf("expected metadata cert path %q, got %q", targetPath, metadata.CertPath)
	}
}

func TestMySQLWritesCaPem(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "ssl", "ca.pem")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-mysql",
		TrustStoreType: "mysql_ssl_ca",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: targetPath,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Fatal("expected PEM content in ca.pem")
	}
}

func TestOracleWalletAdd(t *testing.T) {
	dir := t.TempDir()
	walletDir := filepath.Join(dir, "wallet")
	executor := &mockCommandExecutor{}
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-oracle",
		TrustStoreType: "oracle_wallet",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: walletDir,
		Executor:       executor,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 orapki call, got %d: %v", len(executor.calls), executor.calls)
	}
	if !strings.Contains(executor.calls[0], "orapki wallet add") {
		t.Fatalf("expected wallet add in %q", executor.calls[0])
	}
	if !strings.Contains(executor.calls[0], walletDir) {
		t.Fatalf("expected wallet dir in %q", executor.calls[0])
	}
}

func TestInvalidPEM(t *testing.T) {
	inst := Installer{}
	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-pg",
		TrustStoreType: "postgresql_ssl_root",
		MaterialType:   "trust_anchor",
		ChainPem:       "not-a-pem",
		TrustStorePath: filepath.Join(t.TempDir(), "root.crt"),
	})
	if err == nil {
		t.Fatal("expected malformed PEM rejection")
	}
	if installer.ErrorCode(err) != "ERR_INVALID_PEM" {
		t.Fatalf("expected ERR_INVALID_PEM, got %q", installer.ErrorCode(err))
	}
}

func TestIdempotentThumbprint(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "ca.pem")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	opts := installer.InstallOptions{
		AssignmentID:   "assign-mysql",
		TrustStoreType: "mysql_ssl_ca",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: targetPath,
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
		t.Fatalf("expected idempotent log, got %q (first %q)", secondLog, firstLog)
	}
}

func TestExpandTrustStorePathWithTilde(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}

	expanded, err := ExpandTrustStorePath("~/.postgresql/root.crt", currentUser.Username)
	if err != nil {
		t.Fatalf("expand path: %v", err)
	}

	expected := filepath.Join(currentUser.HomeDir, ".postgresql", "root.crt")
	if expanded != expected {
		t.Fatalf("expected %q, got %q", expected, expanded)
	}
}
