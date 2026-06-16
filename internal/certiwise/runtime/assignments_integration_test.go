package runtime

import (
	"testing"

	"github.com/bluewave-labs/capture/internal/certiwise"
	"github.com/bluewave-labs/capture/internal/installer"
)

func TestLinuxInstallerRegistered(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("linux_update_ca_certificates")
	if !ok {
		t.Fatal("expected linux installer to be registered")
	}
	if !inst.Supports("trust_anchor", "linux_update_ca_certificates") {
		t.Fatal("linux installer should support trust_anchor")
	}
	if inst.Supports("server_identity", "linux_update_ca_certificates") {
		t.Fatal("linux installer should not support server_identity")
	}
}

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

	aliasAssignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-alias",
		TrustStoreType: "linux_update_ca_certificates",
		Config: certiwise.AssignmentConfig{
			Alias: "internal-ca",
		},
	}
	aliasRecord := buildInstallRecord(
		aliasAssignment,
		"thumb",
		installer.InstallOptions{
			AssignmentID: "assign-alias",
			Alias:        "internal-ca",
		},
	)
	if aliasRecord.CertPath != "/usr/local/share/ca-certificates/compliwise-internal-ca.crt" {
		t.Fatalf("unexpected alias cert path %q", aliasRecord.CertPath)
	}
}

func TestJavaInstallerSupportsBothTypes(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("java_cacerts")
	if !ok {
		t.Fatal("expected java installer")
	}
	if !inst.Supports("trust_anchor", "java_cacerts") {
		t.Fatal("java installer should support trust_anchor on java_cacerts")
	}

	pkcs12Inst, ok := defaultInstallRegistry.Lookup("java_pkcs12")
	if !ok {
		t.Fatal("expected java_pkcs12 installer")
	}
	if pkcs12Inst != inst {
		t.Fatal("expected same java installer instance for java_pkcs12")
	}
	if !pkcs12Inst.Supports("server_identity", "java_pkcs12") {
		t.Fatal("java installer should support server_identity on java_pkcs12")
	}
}

func TestPythonInstallerRegistered(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("python_certifi_bundle")
	if !ok {
		t.Fatal("expected python installer to be registered")
	}
	if !inst.Supports("trust_anchor", "python_certifi_bundle") {
		t.Fatal("python installer should support trust_anchor")
	}
	if inst.Supports("server_identity", "python_certifi_bundle") {
		t.Fatal("python installer should not support server_identity")
	}
}

func TestDotnetInstallerRegistered(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("dotnet_root_store")
	if !ok {
		t.Fatal("expected dotnet installer to be registered")
	}
	if !inst.Supports("trust_anchor", "dotnet_root_store") {
		t.Fatal("dotnet installer should support trust_anchor")
	}
	if inst.Supports("server_identity", "dotnet_root_store") {
		t.Fatal("dotnet installer should not support server_identity")
	}
}

func TestMacosInstallerRegistered(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("macos_keychain_system")
	if !ok {
		t.Fatal("expected macos installer to be registered")
	}
	if !inst.Supports("trust_anchor", "macos_keychain_system") {
		t.Fatal("macos installer should support trust_anchor")
	}
	if inst.Supports("server_identity", "macos_keychain_system") {
		t.Fatal("macos installer should not support server_identity")
	}
}

func TestBuildInstallRecordMacosKeychainPaths(t *testing.T) {
	assignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-macos",
		TrustStoreType: "macos_keychain_system",
		Config: certiwise.AssignmentConfig{
			KeychainPath: "/Library/Keychains/System.keychain",
			Alias:        "swift-gateway",
		},
	}
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			KeychainPath: "/Library/Keychains/System.keychain",
			Alias:        "swift-gateway",
		},
	)
	if record.KeychainPath != "/Library/Keychains/System.keychain" {
		t.Fatalf("unexpected keychain path %q", record.KeychainPath)
	}
	if record.Alias != "swift-gateway" {
		t.Fatalf("unexpected alias %q", record.Alias)
	}
}

func TestBuildInstallRecordDotnetPaths(t *testing.T) {
	assignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-dotnet",
		TrustStoreType: "dotnet_root_store",
		Config: certiwise.AssignmentConfig{
			TrustStorePath: "/etc/compliwise/dotnet/trust.pem",
			Alias:          "dotnet-api",
			EnvFilePath:    "/etc/compliwise/env/dotnet-api.env",
			PreferOsStore:  false,
		},
	}
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			TrustStorePath: "/etc/compliwise/dotnet/trust.pem",
			Alias:          "dotnet-api",
			EnvFilePath:    "/etc/compliwise/env/dotnet-api.env",
		},
	)
	if record.CertPath != "/etc/compliwise/dotnet/trust.pem" {
		t.Fatalf("unexpected cert path %q", record.CertPath)
	}
	if record.EnvFilePath != "/etc/compliwise/env/dotnet-api.env" {
		t.Fatalf("unexpected env file path %q", record.EnvFilePath)
	}
	if record.PreferOsStore {
		t.Fatal("expected PreferOsStore false for bundle path install")
	}

	osAssignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-dotnet-os",
		TrustStoreType: "dotnet_root_store",
		Config: certiwise.AssignmentConfig{
			TrustStorePath: "/usr/local/share/ca-certificates",
			Alias:          "dotnet-ca",
			PreferOsStore:  true,
		},
	}
	osRecord := buildInstallRecord(
		osAssignment,
		"thumb",
		installer.InstallOptions{
			TrustStorePath: "/usr/local/share/ca-certificates",
			Alias:          "dotnet-ca",
		},
	)
	if !osRecord.PreferOsStore {
		t.Fatal("expected PreferOsStore true for OS delegation")
	}
}

func TestNodeExtraCACertsRegistrySupportsTrustAnchor(t *testing.T) {
	inst, ok := defaultInstallRegistry.Lookup("node_extra_ca_certs")
	if !ok {
		t.Fatal("expected node installer to be registered")
	}
	if !inst.Supports("trust_anchor", "node_extra_ca_certs") {
		t.Fatal("node installer should support trust_anchor")
	}
	if inst.Supports("server_identity", "node_extra_ca_certs") {
		t.Fatal("node installer should not support server_identity")
	}
}

func TestBuildInstallRecordNodePaths(t *testing.T) {
	assignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-node",
		TrustStoreType: "node_extra_ca_certs",
		Config: certiwise.AssignmentConfig{
			TrustStorePath: "/etc/compliwise/ca-bundles",
			Alias:          "webhook-dispatcher",
			EnvFilePath:    "/etc/compliwise/env.d/node_extra_ca",
		},
	}
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			TrustStorePath: "/etc/compliwise/ca-bundles",
			Alias:          "webhook-dispatcher",
			EnvFilePath:    "/etc/compliwise/env.d/node_extra_ca",
		},
	)
	expected := "/etc/compliwise/ca-bundles/compliwise-webhook-dispatcher.pem"
	if record.CertPath != expected {
		t.Fatalf("unexpected cert path %q", record.CertPath)
	}
	if record.EnvFilePath != "/etc/compliwise/env.d/node_extra_ca" {
		t.Fatalf("unexpected env file path %q", record.EnvFilePath)
	}
}

func TestBuildInstallRecordPythonPaths(t *testing.T) {
	assignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-python",
		TrustStoreType: "python_certifi_bundle",
		Config: certiwise.AssignmentConfig{
			TrustStorePath: "/venv/lib/python3.12/site-packages/certifi/cacert.pem",
			PythonVenvPath: "/venv",
			EnvFilePath:    "/etc/compliwise/env.d/requests_ca_bundle",
		},
	}
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			TrustStorePath: "/venv/lib/python3.12/site-packages/certifi/cacert.pem",
			PythonVenvPath: "/venv",
			EnvFilePath:    "/etc/compliwise/env.d/requests_ca_bundle",
		},
	)
	if record.CertPath != "/venv/lib/python3.12/site-packages/certifi/cacert.pem" {
		t.Fatalf("unexpected cert path %q", record.CertPath)
	}
	if record.EnvFilePath != "/etc/compliwise/env.d/requests_ca_bundle" {
		t.Fatalf("unexpected env file path %q", record.EnvFilePath)
	}
}

func TestBuildInstallRecordJavaPaths(t *testing.T) {
	assignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-java",
		TrustStoreType: "java_cacerts",
		Config: certiwise.AssignmentConfig{
			TrustStorePath: "/opt/jdk/lib/security/cacerts",
			Alias:          "payment-api",
		},
	}
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			AssignmentID:   "assign-java",
			TrustStoreType: "java_cacerts",
			TrustStorePath: "/opt/jdk/lib/security/cacerts",
			Alias:          "payment-api",
		},
	)
	if record.TrustStorePath != "/opt/jdk/lib/security/cacerts" {
		t.Fatalf("unexpected trust store path %q", record.TrustStorePath)
	}
	if record.Alias != "compliwise-payment-api" {
		t.Fatalf("unexpected alias %q", record.Alias)
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

func TestDatabaseInstallersRegistered(t *testing.T) {
	for _, trustStoreType := range []string{
		"postgresql_ssl_root",
		"mysql_ssl_ca",
		"oracle_wallet",
	} {
		inst, ok := defaultInstallRegistry.Lookup(trustStoreType)
		if !ok {
			t.Fatalf("expected %s installer to be registered", trustStoreType)
		}
		if !inst.Supports("trust_anchor", trustStoreType) {
			t.Fatalf("%s installer should support trust_anchor", trustStoreType)
		}
		if inst.Supports("server_identity", trustStoreType) {
			t.Fatalf("%s installer should not support server_identity", trustStoreType)
		}
	}
}

func TestBuildInstallRecordPostgreSQLPaths(t *testing.T) {
	assignment := certiwise.AssignmentPullItem{
		AssignmentID:   "assign-pg",
		TrustStoreType: "postgresql_ssl_root",
		MaterialType:   "trust_anchor",
		Config: certiwise.AssignmentConfig{
			TrustStorePath: "/var/lib/postgresql/.postgresql/root.crt",
			DbUser:         "postgres",
		},
	}
	record := buildInstallRecord(
		assignment,
		"thumb",
		installer.InstallOptions{
			TrustStorePath: "/var/lib/postgresql/.postgresql/root.crt",
			DbUser:         "postgres",
			CertFileName:   "root.crt",
		},
	)
	if record.CertPath != "/var/lib/postgresql/.postgresql/root.crt" {
		t.Fatalf("unexpected cert path %q", record.CertPath)
	}
}
