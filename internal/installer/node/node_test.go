package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/testfixtures"
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
		Alias:          "assign-node",
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
	if !strings.Contains(string(envData), "NODE_EXTRA_CA_CERTS="+bundlePath) {
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

	envAfter, err := os.ReadFile(envPath)
	if err == nil && strings.Contains(string(envAfter), "NODE_EXTRA_CA_CERTS") {
		t.Fatal("expected NODE_EXTRA_CA_CERTS cleared from env file")
	}
}

func TestNodeInstallerRejectsMalformedPEM(t *testing.T) {
	inst := Installer{}
	_, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-node",
		TrustStoreType: "node_extra_ca_certs",
		MaterialType:   "trust_anchor",
		ChainPem:       "not-a-pem",
		TrustStorePath: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected malformed PEM rejection")
	}
	if installer.ErrorCode(err) != "ERR_INVALID_PEM" {
		t.Fatalf("expected ERR_INVALID_PEM, got %q", installer.ErrorCode(err))
	}
}

func TestNodeInstallerIdempotentThumbprint(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	opts := installer.InstallOptions{
		AssignmentID:   "assign-node",
		TrustStoreType: "node_extra_ca_certs",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
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

func TestNodeInstallerEnvFileAtomic(t *testing.T) {
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

	if _, err := os.Stat(envPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("expected env temp file to be renamed away")
	}

	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	if !strings.Contains(string(envData), "NODE_EXTRA_CA_CERTS=") {
		t.Fatalf("expected NODE_EXTRA_CA_CERTS assignment in env file")
	}
}

func TestNodeInstallerOpensslCaLog(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	log, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-node",
		TrustStoreType: "node_extra_ca_certs",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: dir,
		UseOpensslCa:   true,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(log, "node --use-openssl-ca") {
		t.Fatalf("expected openssl CA log line, got %q", log)
	}
}

func TestNodeInstallerPathAllowlist(t *testing.T) {
	inst := Installer{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-1",
		TrustStoreType: "node_extra_ca_certs",
		MaterialType:   "trust_anchor",
		ChainPem:       testfixtures.SampleTrustAnchorPEM,
		Thumbprint:     thumbprint,
		TrustStorePath: "/tmp/base",
		Alias:          "../secret",
	})
	if err == nil {
		t.Fatal("expected path traversal rejection")
	}
}
