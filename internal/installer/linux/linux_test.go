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

func TestSanitizeFileNameUsesInstallerHelper(t *testing.T) {
	if got := installer.SanitizeFileName("test.example.com.crt"); got != "test.example.com.crt" {
		t.Fatalf("unexpected sanitize result %q", got)
	}
}
