package pem

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/testfixtures"
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

func TestServerIdentityInstallRemove(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	certPEM, keyPEM, err := testfixtures.ServerIdentityPEM()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	thumbprint, err := installer.ThumbprintFromPEM(certPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:      "assign-srv",
		TrustStoreType:    "pem_directory",
		MaterialType:      "server_identity",
		ChainPem:          certPEM,
		PrivateKeyPem:     keyPEM,
		Thumbprint:        thumbprint,
		CertFileName:      "tls.crt",
		KeyFileName:       "tls.key",
		KeyPermissionMode: "0600",
		TrustStorePath:    dir,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}

	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("expected cert at %s: %v", certPath, err)
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Fatalf("expected cert mode 0644, got %o", certInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected key at %s: %v", keyPath, err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected key mode 0600, got %o", keyInfo.Mode().Perm())
	}

	_, err = inst.Remove(t.Context(), installer.RemoveOptions{
		AssignmentID:   "assign-srv",
		TrustStoreType: "pem_directory",
		Record: installer.InstallRecord{
			CertPath: certPath,
			KeyPath:  keyPath,
		},
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("expected removed cert")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("expected removed key")
	}
}

func TestServerIdentityKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	certPEM, _, err := testfixtures.ServerIdentityPEM()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	_, otherKeyPEM, err := testfixtures.ServerIdentityPEM()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	_, err = inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-srv",
		TrustStoreType: "pem_directory",
		MaterialType:   "server_identity",
		ChainPem:       certPEM,
		PrivateKeyPem:  otherKeyPEM,
		TrustStorePath: dir,
	})
	if err == nil {
		t.Fatal("expected key mismatch error")
	}
	var coded *installer.CodedError
	if !errors.As(err, &coded) || coded.Code != "ERR_KEY_MISMATCH" {
		t.Fatalf("expected ERR_KEY_MISMATCH, got %v", err)
	}
}

func TestServerIdentityReloadFailure(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	certPEM, keyPEM, err := testfixtures.ServerIdentityPEM()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	log, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-srv",
		TrustStoreType: "pem_directory",
		MaterialType:   "server_identity",
		ChainPem:       certPEM,
		PrivateKeyPem:  keyPEM,
		CertFileName:   "tls.crt",
		KeyFileName:    "tls.key",
		TrustStorePath: dir,
		ReloadCommand:  []string{"false"},
	})
	if err == nil {
		t.Fatal("expected reload failure")
	}
	var coded *installer.CodedError
	if !errors.As(err, &coded) || coded.Code != "ERR_RELOAD_FAILED" {
		t.Fatalf("expected ERR_RELOAD_FAILED, got %v", err)
	}

	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	if _, statErr := os.Stat(certPath); statErr != nil {
		t.Fatalf("expected cert retained after reload failure: %v", statErr)
	}
	if _, statErr := os.Stat(keyPath); statErr != nil {
		t.Fatalf("expected key retained after reload failure: %v", statErr)
	}
	if strings.Contains(log, "BEGIN PRIVATE KEY") || strings.Contains(log, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("installer log must not contain private key material")
	}
}

func TestServerIdentityLogRedaction(t *testing.T) {
	dir := t.TempDir()
	inst := Installer{}
	certPEM, keyPEM, err := testfixtures.ServerIdentityPEM()
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	log, err := inst.Install(t.Context(), installer.InstallOptions{
		AssignmentID:   "assign-srv",
		TrustStoreType: "pem_directory",
		MaterialType:   "server_identity",
		ChainPem:       certPEM,
		PrivateKeyPem:  keyPEM,
		CertFileName:   "tls.crt",
		KeyFileName:    "tls.key",
		TrustStorePath: dir,
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if strings.Contains(log, "BEGIN PRIVATE KEY") || strings.Contains(log, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("installer log must not contain private key material: %q", log)
	}
}

func TestPemInstallerSupportsServerIdentity(t *testing.T) {
	inst := Installer{}
	if !inst.Supports("server_identity", "pem_directory") {
		t.Fatal("expected server_identity support")
	}
	if inst.Supports("server_identity", "java_cacerts") {
		t.Fatal("server_identity should not support java_cacerts")
	}
}
