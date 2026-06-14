package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/testfixtures"
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
