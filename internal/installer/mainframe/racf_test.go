package mainframe

import (
	"errors"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/testfixtures"
)

type mockCommandExecutor struct {
	calls []string
}

func (m *mockCommandExecutor) Run(name string, args ...string) ([]byte, error) {
	call := name
	if len(args) > 0 {
		call += " " + strings.Join(args, " ")
	}
	m.calls = append(m.calls, call)
	return []byte("OK"), nil
}

func TestBuildTrustCommand(t *testing.T) {
	command := BuildTrustCommand("COMPLIUSR", "/tmp/compliwise-assign.pem")
	if !strings.Contains(command, "RACDCERT") {
		t.Fatalf("expected RACDCERT in %q", command)
	}
	if !strings.Contains(command, "ID(COMPLIUSR)") {
		t.Fatalf("expected profile in %q", command)
	}
	if !strings.Contains(command, "TRUST WITH(CERT('/tmp/compliwise-assign.pem'))") {
		t.Fatalf("expected cert path in %q", command)
	}
}

func TestBuildDeleteCommand(t *testing.T) {
	command := BuildDeleteCommand("COMPLIUSR", "root-ca")
	if !strings.Contains(command, "RACDCERT DELETE(COMPLIUSR)-LABEL(root-ca)") {
		t.Fatalf("unexpected delete command %q", command)
	}
}

func TestBuildDeleteCommandDefaultLabel(t *testing.T) {
	command := BuildDeleteCommand("COMPLIUSR", "")
	if !strings.Contains(command, "LABEL(TRUST)") {
		t.Fatalf("expected default label in %q", command)
	}
}

func TestTempCertPathSanitizesAssignmentID(t *testing.T) {
	path := TempCertPath("assign/123")
	if !strings.HasPrefix(path, "/tmp/compliwise-") {
		t.Fatalf("unexpected temp path %q", path)
	}
	if strings.Contains(path, "/") && strings.Count(path, "/") > 2 {
		t.Fatalf("path should not contain slashes from assignment id: %q", path)
	}
}

func TestInstallRunsRacfTrustCommand(t *testing.T) {
	executor := &mockCommandExecutor{}
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	metadata := &installer.InstallRecord{}
	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-mf-1",
		TrustStoreType: "mainframe_racf",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		RacfProfile:    "COMPLIUSR",
		SystemID:       "SYS1",
		Executor:       executor,
		Metadata:       metadata,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 racf call, got %d: %v", len(executor.calls), executor.calls)
	}
	if !strings.Contains(executor.calls[0], "RACDCERT ID(COMPLIUSR) TRUST") {
		t.Fatalf("unexpected racf call %q", executor.calls[0])
	}
	if metadata.Thumbprint != thumbprint {
		t.Fatalf("metadata thumbprint mismatch")
	}
}

func TestInstallGatewayModeSkipsRacf(t *testing.T) {
	executor := &mockCommandExecutor{}
	inst := Installer{}

	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-mf-gateway",
		TrustStoreType: "mainframe_racf",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		RacfProfile:    "COMPLIUSR",
		SystemID:       "SYS1",
		GatewayMode:    true,
		Executor:       executor,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("gateway mode should not invoke racf, got %v", executor.calls)
	}
}

func TestInstallRequiresRacfProfile(t *testing.T) {
	inst := Installer{}
	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-mf-missing-profile",
		TrustStoreType: "mainframe_racf",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
	})
	if err == nil {
		t.Fatal("expected error for missing racfProfile")
	}
	var coded *installer.CodedError
	if !errors.As(err, &coded) || coded.Code != "ERR_INVALID_CONFIG" {
		t.Fatalf("expected ERR_INVALID_CONFIG, got %v", err)
	}
}

func TestRemoveRunsRacfDelete(t *testing.T) {
	executor := &mockCommandExecutor{}
	inst := Installer{}

	_, err := inst.Remove(t.Context(), installer.RemoveOptions{
		TrustStoreType: "mainframe_racf",
		Executor:       executor,
		Record: installer.InstallRecord{
			AssignmentID: "assign-mf-1",
			Alias:        "COMPLIUSR",
			CertPath:     "/tmp/compliwise-assign-mf-1.pem",
		},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 racf delete call, got %d", len(executor.calls))
	}
	if !strings.Contains(executor.calls[0], "RACDCERT DELETE(COMPLIUSR)") {
		t.Fatalf("unexpected delete call %q", executor.calls[0])
	}
}

func TestSupportsOnlyMainframeTrustAnchor(t *testing.T) {
	inst := Installer{}
	if !inst.Supports("trust_anchor", "mainframe_racf") {
		t.Fatal("expected support for mainframe_racf trust_anchor")
	}
	if inst.Supports("server_identity", "mainframe_racf") {
		t.Fatal("did not expect support for server_identity")
	}
	if inst.Supports("trust_anchor", "java_cacerts") {
		t.Fatal("did not expect support for java_cacerts")
	}
}
