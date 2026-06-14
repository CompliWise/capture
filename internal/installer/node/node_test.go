package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/testfixtures"
)

func TestNodeInstallerInstallRemove(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "node.env")
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-node",
		TrustStoreType: "node_extra_ca_certs",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: dir,
		EnvFilePath:    envPath,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	bundlePath := filepath.Join(dir, "compliwise-assign-node.pem")
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("expected bundle file: %v", err)
	}

	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	if !strings.Contains(string(envData), bundlePath) {
		t.Fatalf("expected NODE_EXTRA_CA_CERTS in env file")
	}

	_, err = inst.Remove(t.Context(), installer.RemoveOptions{
		AssignmentID:   "assign-node",
		TrustStoreType: "node_extra_ca_certs",
		Record: installer.InstallRecord{
			CertPath:    bundlePath,
			EnvFilePath: envPath,
		},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := os.Stat(bundlePath); !os.IsNotExist(err) {
		t.Fatal("expected bundle removed")
	}
}
