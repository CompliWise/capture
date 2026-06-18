package macos

import (
	"fmt"
	"runtime"
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

func TestTrustAnchorAddTrustedCert(t *testing.T) {
	executor := &mockCommandExecutor{}
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	metadata := &installer.InstallRecord{}
	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-macos",
		TrustStoreType: "macos_keychain_system",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		Executor:       executor,
		Metadata:       metadata,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 security call, got %d: %v", len(executor.calls), executor.calls)
	}
	call := executor.calls[0]
	if !strings.Contains(call, "security add-trusted-cert") {
		t.Fatalf("expected add-trusted-cert in %q", call)
	}
	if !strings.Contains(call, DefaultSystemKeychain) {
		t.Fatalf("expected system keychain in %q", call)
	}
	if metadata.KeychainPath != DefaultSystemKeychain {
		t.Fatalf("expected metadata keychain path %q, got %q", DefaultSystemKeychain, metadata.KeychainPath)
	}
	if metadata.CertCommonName != "test.local" {
		t.Fatalf("expected common name test.local, got %q", metadata.CertCommonName)
	}
}

func TestRemoveByCommonName(t *testing.T) {
	executor := &mockCommandExecutor{}
	log, err := removeFromKeychain(installer.InstallRecord{
		CertCommonName: "test.local",
		KeychainPath:   DefaultSystemKeychain,
	}, executor)
	if err != nil {
		t.Fatalf("removeFromKeychain: %v\nlog: %s", err, log)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 security call, got %d", len(executor.calls))
	}
	if !strings.Contains(executor.calls[0], "security delete-certificate -c test.local") {
		t.Fatalf("expected delete-certificate -c test.local in %q", executor.calls[0])
	}
	if !strings.Contains(executor.calls[0], DefaultSystemKeychain) {
		t.Fatalf("expected keychain path in %q", executor.calls[0])
	}
}

func TestPlatformMismatch(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("platform mismatch test requires non-darwin host")
	}

	inst := Installer{}
	_, err := inst.Install(t.Context(), installer.InstallOptions{
		TrustStoreType: "macos_keychain_system",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
	})
	if err == nil {
		t.Fatal("expected platform mismatch")
	}
	if installer.ErrorCode(err) != "ERR_PLATFORM_MISMATCH" {
		t.Fatalf("expected ERR_PLATFORM_MISMATCH, got %q", installer.ErrorCode(err))
	}
}

func TestPermissionErrorMapping(t *testing.T) {
	executor := &mockCommandExecutor{
		calls: nil,
	}
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	permissionExec := &permissionDeniedExecutor{}
	_, installErr := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-macos",
		TrustStoreType: "macos_keychain_system",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		Executor:       permissionExec,
	})
	if installErr == nil {
		t.Fatal("expected permission error")
	}
	if installer.ErrorCode(installErr) != "ERR_PERMISSION" {
		t.Fatalf("expected ERR_PERMISSION, got %q", installer.ErrorCode(installErr))
	}
	_ = executor
}

type permissionDeniedExecutor struct{}

func (permissionDeniedExecutor) Run(_ string, _ ...string) ([]byte, error) {
	return []byte("permission denied"), fmt.Errorf("authorization failed")
}

func TestInvalidPEM(t *testing.T) {
	inst := Installer{}
	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-macos",
		TrustStoreType: "macos_keychain_system",
		MaterialType:   "trust_anchor",
		ChainPem:       "not-a-pem",
		Executor:       &mockCommandExecutor{},
	})
	if err == nil {
		t.Fatal("expected malformed PEM rejection")
	}
	if installer.ErrorCode(err) != "ERR_INVALID_PEM" {
		t.Fatalf("expected ERR_INVALID_PEM, got %q", installer.ErrorCode(err))
	}
}
