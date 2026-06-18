package java

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeytoolAliasPrefixesCompliwise(t *testing.T) {
	if got := KeytoolAlias("assign-1", "payment-api"); got != "compliwise-payment-api" {
		t.Fatalf("expected compliwise-payment-api, got %q", got)
	}
	if got := KeytoolAlias("assign-1", "compliwise-existing"); got != "compliwise-existing" {
		t.Fatalf("expected unchanged prefixed alias, got %q", got)
	}
	if got := KeytoolAlias("assign-42", ""); got != "compliwise-assign-42" {
		t.Fatalf("expected assignment fallback, got %q", got)
	}
}

func TestImportCertArgsShape(t *testing.T) {
	args := ImportCertArgs("keytool", "compliwise-demo", "/tmp/cert.pem", "/tmp/cacerts", "secret")
	if len(args) != 11 || args[0] != "keytool" || args[1] != "-importcert" {
		t.Fatalf("unexpected args: %v", args)
	}
	if args[10] != "secret" {
		t.Fatalf("expected password at end of args")
	}
}

func TestSanitizeInstallerLogRedactsStorepassAndPrivateKey(t *testing.T) {
	raw := strings.Join([]string{
		"keytool -importcert -storepass hunter2 done",
		"ref env:JAVA_CACERTS_PASSWORD",
		"-----BEGIN PRIVATE KEY-----",
		"secret-key-material",
		"-----END PRIVATE KEY-----",
	}, "\n")

	sanitized := SanitizeInstallerLog(raw)
	if strings.Contains(sanitized, "hunter2") {
		t.Fatal("password should be redacted")
	}
	if strings.Contains(sanitized, "JAVA_CACERTS_PASSWORD") {
		t.Fatal("env ref should be redacted")
	}
	if strings.Contains(sanitized, "secret-key-material") {
		t.Fatal("private key body should be redacted")
	}
	if !strings.Contains(sanitized, "[REDACTED]") && !strings.Contains(sanitized, "[PRIVATE KEY REDACTED]") {
		t.Fatal("expected redaction marker")
	}
}

func TestResolveStorePasswordRefEnv(t *testing.T) {
	t.Setenv("TEST_JVM_STORE_PASSWORD", "from-env")
	pwd, err := ResolveStorePasswordRef("env:TEST_JVM_STORE_PASSWORD")
	if err != nil || pwd != "from-env" {
		t.Fatalf("ResolveStorePasswordRef: pwd=%q err=%v", pwd, err)
	}
}

func TestResolveStorePasswordRefFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pass.txt")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pwd, err := ResolveStorePasswordRef("file:" + path)
	if err != nil || pwd != "file-secret" {
		t.Fatalf("ResolveStorePasswordRef file: pwd=%q err=%v", pwd, err)
	}
}

func TestResolveCacertsPathOpenJDK11(t *testing.T) {
	home := t.TempDir()
	cacerts := filepath.Join(home, "lib", "security", "cacerts")
	if err := os.MkdirAll(filepath.Dir(cacerts), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacerts, []byte("ks"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveCacertsPath(home); got != cacerts {
		t.Fatalf("expected %q, got %q", cacerts, got)
	}
}

func TestResolveCacertsPathOpenJDK8(t *testing.T) {
	home := t.TempDir()
	cacerts := filepath.Join(home, "jre", "lib", "security", "cacerts")
	if err := os.MkdirAll(filepath.Dir(cacerts), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacerts, []byte("ks"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveCacertsPath(home); got != cacerts {
		t.Fatalf("expected %q, got %q", cacerts, got)
	}
}

func TestResolveKeystorePathJavaCacertsRequiresHome(t *testing.T) {
	t.Setenv("JAVA_HOME", "")
	if _, err := ResolveKeystorePath("java_cacerts", "", ""); err == nil {
		t.Fatal("expected error when path and java home missing")
	}
}

func TestParseAliasThumbprintFromList(t *testing.T) {
	output := "Alias name: compliwise-demo\nSHA256: AB:CD:EF:01\n"
	got := parseAliasThumbprintFromList(output)
	if got != "abcdef01" {
		t.Fatalf("unexpected thumbprint %q", got)
	}
}

func TestInstallerSupportsJvmTypes(t *testing.T) {
	inst := Installer{}
	if !inst.Supports("trust_anchor", "java_cacerts") {
		t.Fatal("expected java_cacerts trust_anchor")
	}
	if !inst.Supports("server_identity", "java_pkcs12") {
		t.Fatal("expected java_pkcs12 server_identity")
	}
	if inst.Supports("server_identity", "java_cacerts") {
		t.Fatal("java_cacerts should not support server_identity")
	}
}
