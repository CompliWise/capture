package runtime

import (
	"testing"

	"github.com/bluewave-labs/capture/internal/certiwise"
	"github.com/bluewave-labs/capture/internal/installer"
)

func TestDefaultRegistryDispatchesJavaNotLinux(t *testing.T) {
	javaInst, ok := defaultInstallRegistry.Lookup("java_cacerts")
	if !ok {
		t.Fatal("expected java installer")
	}
	if !javaInst.Supports("trust_anchor", "java_cacerts") {
		t.Fatal("java installer should support trust_anchor")
	}

	linuxInst, ok := defaultInstallRegistry.Lookup("linux_update_ca_certificates")
	if !ok {
		t.Fatal("expected linux installer")
	}
	if javaInst == linuxInst {
		t.Fatal("expected distinct installer instances")
	}
}

func TestWindowsInstallerRegistered(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("windows_cert_store")
	if !ok {
		t.Fatal("expected windows installer to be registered")
	}
	if !inst.Supports("trust_anchor", "windows_cert_store") {
		t.Fatal("windows installer should support trust_anchor")
	}
	if !inst.Supports("server_identity", "windows_cert_store") {
		t.Fatal("windows installer should support server_identity")
	}
}

func TestBuildInstallRecordServerIdentityPaths(t *testing.T) {
	assignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-server",
		TrustStoreType: "pem_directory",
		MaterialType:   "server_identity",
		Config: certiwise.AssignmentConfig{
			TrustStorePath: "/etc/fastapi/tls",
			CertFileName:   "tls.crt",
			KeyFileName:    "tls.key",
		},
	}
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			CertFileName:   "tls.crt",
			KeyFileName:    "tls.key",
			TrustStorePath: "/etc/fastapi/tls",
		},
	)
	if record.CertPath != "/etc/fastapi/tls/tls.crt" {
		t.Fatalf("unexpected cert path %q", record.CertPath)
	}
	if record.KeyPath != "/etc/fastapi/tls/tls.key" {
		t.Fatalf("unexpected key path %q", record.KeyPath)
	}
}

func TestBuildInstallRecordLinuxPath(t *testing.T) {
	assignment := certiwiseAssignment("linux_update_ca_certificates", "/custom/ca")
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			CertFileName:   "demo.crt",
			TrustStorePath: "/custom/ca",
		},
	)
	if record.CertPath != "/custom/ca/demo.crt" {
		t.Fatalf("unexpected cert path %q", record.CertPath)
	}
}

func TestPemInstallerSupportsServerIdentity(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("pem_directory")
	if !ok {
		t.Fatal("expected pem installer")
	}
	if !inst.Supports("server_identity", "pem_directory") {
		t.Fatal("pem installer should support server_identity")
	}
}

func certiwiseAssignment(trustStoreType, trustStorePath string) certiwise.AssignmentPullItem {
	return certiwise.AssignmentPullItem{
		AssignmentID:   "assign-1",
		TrustStoreType: trustStoreType,
		Config: certiwise.AssignmentConfig{
			TrustStorePath: trustStorePath,
			CertFileName:   "demo.crt",
		},
	}
}
