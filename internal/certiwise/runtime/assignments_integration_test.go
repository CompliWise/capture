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

func TestUnsupportedTrustStoreType(t *testing.T) {
	if _, ok := defaultInstallRegistry.Lookup("windows_cert_store"); ok {
		t.Fatal("windows installer should not be registered")
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
