package pem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/testfixtures"
)

func TestPemInstallerInstallRemove(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}

	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-pem",
		TrustStoreType: "pem_directory",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		CertFileName:   "tls.crt",
		TrustStorePath: dir,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	destPath := filepath.Join(dir, "tls.crt")
	if _, err := os.Stat(destPath); err != nil {
		t.Fatalf("expected cert at %s: %v", destPath, err)
	}

	_, err = inst.Remove(t.Context(), installer.RemoveOptions{
		AssignmentID:   "assign-pem",
		TrustStoreType: "pem_directory",
		Record: installer.InstallRecord{
			CertPath: destPath,
		},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Fatalf("expected removed cert")
	}
}

func TestPemInstallerIdempotent(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	opts := installer.InstallOptions{
		AssignmentID:   "assign-pem",
		TrustStoreType: "pem_directory",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		CertFileName:   "tls.crt",
		TrustStorePath: dir,
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
