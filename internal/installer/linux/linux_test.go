package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/testfixtures"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("COMPLIWISE_SKIP_CA_UPDATE", "1")
	os.Exit(m.Run())
}

func TestInstallLinuxUpdateCACertificatesWritesFile(t *testing.T) {
	dir := t.TempDir()

	logOutput, err := InstallLinuxUpdateCACertificates(InstallOptions{
		CertFileName:   "test.example.com.crt",
		TrustStorePath: dir,
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
	})
	if err != nil {
		t.Fatalf("InstallLinuxUpdateCACertificates: %v\nlog: %s", err, logOutput)
	}

	destPath := filepath.Join(dir, "test.example.com.crt")
	if _, err := os.Stat(destPath); err != nil {
		t.Fatalf("expected certificate file at %s: %v", destPath, err)
	}
}

func TestInstallLinuxUpdateCACertificatesIdempotent(t *testing.T) {
	dir := t.TempDir()
	opts := InstallOptions{
		CertFileName:   "test.example.com.crt",
		TrustStorePath: dir,
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
	}

	if _, err := InstallLinuxUpdateCACertificates(opts); err != nil {
		t.Fatalf("first install: %v", err)
	}

	thumbprint, err := fileThumbprint(filepath.Join(dir, "test.example.com.crt"))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	opts.Thumbprint = thumbprint

	secondLog, err := InstallLinuxUpdateCACertificates(opts)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !strings.Contains(secondLog, "idempotent") {
		t.Fatalf("expected idempotent log, got %q", secondLog)
	}
}

func TestInstallUsesCompliwiseAliasFilename(t *testing.T) {
	dir := t.TempDir()

	_, err := InstallLinuxUpdateCACertificates(InstallOptions{
		AssignmentID:   "assign-1",
		TrustStorePath: dir,
		Alias:          "internal-ca",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	destPath := filepath.Join(dir, "compliwise-internal-ca.crt")
	if _, err := os.Stat(destPath); err != nil {
		t.Fatalf("expected %s: %v", destPath, err)
	}
}

func TestInstallSUSEUsesPemExtension(t *testing.T) {
	dir := t.TempDir()

	_, fileName, profile := resolveInstallTarget(InstallOptions{
		AssignmentID:   "assign-suse",
		TrustStorePath: "/etc/pki/trust/anchors",
		Alias:          "corp-root",
	})
	if profile.Kind != DistroSUSE || fileName != "compliwise-corp-root.pem" {
		t.Fatalf("profile=%+v fileName=%q", profile, fileName)
	}

	_, err := InstallLinuxUpdateCACertificates(InstallOptions{
		AssignmentID:   "assign-suse",
		TrustStorePath: dir,
		Alias:          "corp-root",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		CertFileName:   "compliwise-corp-root.pem",
	})
	if err != nil {
		t.Fatalf("install with explicit pem name: %v", err)
	}

	destPath := filepath.Join(dir, "compliwise-corp-root.pem")
	if _, err := os.Stat(destPath); err != nil {
		t.Fatalf("expected %s: %v", destPath, err)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	dir := t.TempDir()

	_, err := InstallLinuxUpdateCACertificates(InstallOptions{
		TrustStorePath: dir,
		CertFileName:   "../escape.crt",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
	})
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLinuxInstallerRemove(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	destPath := filepath.Join(dir, "test.example.com.crt")

	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-1",
		TrustStoreType: "linux_update_ca_certificates",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		CertFileName:   "test.example.com.crt",
		TrustStorePath: dir,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	_, err = inst.Remove(t.Context(), installer.RemoveOptions{
		AssignmentID:   "assign-1",
		TrustStoreType: "linux_update_ca_certificates",
		Record: installer.InstallRecord{
			AssignmentID:   "assign-1",
			TrustStoreType: "linux_update_ca_certificates",
			CertPath:       destPath,
		},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Fatalf("expected cert removed, stat err=%v", err)
	}
}

func TestCertPathForOptionsUsesAlias(t *testing.T) {
	got := CertPathForOptions(InstallOptions{
		AssignmentID:   "assign-abc",
		TrustStorePath: "/custom/ca",
		Alias:          "payments-root",
	})
	want := "/custom/ca/compliwise-payments-root.crt"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLinuxInstallerSupportsTrustAnchorOnly(t *testing.T) {
	inst := Installer{}
	if !inst.Supports("trust_anchor", "linux_update_ca_certificates") {
		t.Fatal("expected trust_anchor support")
	}
	if inst.Supports("server_identity", "linux_update_ca_certificates") {
		t.Fatal("server_identity should not be supported")
	}
}

func TestSanitizeFileNameUsesInstallerHelper(t *testing.T) {
	if got := installer.SanitizeFileName("test.example.com.crt"); got != "test.example.com.crt" {
		t.Fatalf("unexpected sanitize result %q", got)
	}
}

func TestVerifyTLSRejectsMissingBundle(t *testing.T) {
	err := VerifyTLS("https://example.com", "", "")
	if err == nil {
		t.Fatal("expected verify error")
	}
	if installer.ErrorCode(err) != "ERR_VERIFY_FAILED" {
		t.Fatalf("expected ERR_VERIFY_FAILED, got %q", installer.ErrorCode(err))
	}
}
