package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	keytoolSampleThumbprint1 = "1cf843147ed4086ad39717ccc6a3aa8d2be68cb901816ec7feba0e3ded864493"
	keytoolSampleThumbprint2 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func TestParseKeytoolVerboseOutput(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "keytool-sample.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	items := parseKeytoolVerboseOutput(string(data), "/opt/jvm/lib/security/cacerts")
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	if items[0].Alias != "compliwise-test-ca" {
		t.Fatalf("expected first alias, got %q", items[0].Alias)
	}
	if items[0].Thumbprint != keytoolSampleThumbprint1 {
		t.Fatalf("unexpected thumbprint: %q", items[0].Thumbprint)
	}
	if items[0].Source != SourceJavaCacerts {
		t.Fatalf("expected java_cacerts source, got %q", items[0].Source)
	}
	if items[0].TrustStoreType != "java_cacerts" {
		t.Fatalf("expected java_cacerts trust store type, got %q", items[0].TrustStoreType)
	}
	if items[0].NotAfter == "" {
		t.Fatal("expected notAfter to be parsed")
	}

	if items[1].Thumbprint != keytoolSampleThumbprint2 {
		t.Fatalf("unexpected second thumbprint: %q", items[1].Thumbprint)
	}
}

func TestResolveCacertsPath(t *testing.T) {
	dir := t.TempDir()
	modern := filepath.Join(dir, "lib", "security")
	if err := os.MkdirAll(modern, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	modernFile := filepath.Join(modern, "cacerts")
	if err := os.WriteFile(modernFile, []byte("ks"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := resolveCacertsPath(dir); got != modernFile {
		t.Fatalf("expected modern cacerts path %q, got %q", modernFile, got)
	}

	legacyDir := t.TempDir()
	legacy := filepath.Join(legacyDir, "jre", "lib", "security")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	legacyFile := filepath.Join(legacy, "cacerts")
	if err := os.WriteFile(legacyFile, []byte("ks"), 0o644); err != nil {
		t.Fatalf("write legacy: %v", err)
	}
	if got := resolveCacertsPath(legacyDir); got != legacyFile {
		t.Fatalf("expected legacy cacerts path %q, got %q", legacyFile, got)
	}
}

func TestScanJavaCacertsTruncationMetadata(t *testing.T) {
	items, meta := ScanJavaCacerts(JavaScanOptions{Enabled: false}, 100)
	if len(items) != 0 {
		t.Fatalf("expected no items when disabled, got %d", len(items))
	}
	if meta.JavaCacertsTruncated {
		t.Fatal("expected no truncation metadata when disabled")
	}

	_, enabledMeta := ScanJavaCacerts(JavaScanOptions{
		Enabled: true,
		MaxJvms: 1,
	}, 100)
	if enabledMeta.JavaCacertsJvmTotal > 1 && !enabledMeta.JavaCacertsTruncated {
		t.Fatal("expected truncated metadata when JVM count exceeds max")
	}
	if enabledMeta.JavaCacertsJvmScanned > 0 && enabledMeta.JavaCacertsJvmScanned > 1 {
		t.Fatalf("expected at most 1 scanned JVM, got %d", enabledMeta.JavaCacertsJvmScanned)
	}
}

func TestCapJavaHomesMetadata(t *testing.T) {
	homes, meta := capJavaHomes([]string{
		"/jvm/c",
		"/jvm/b",
		"/jvm/a",
		"/jvm/d",
		"/jvm/e",
		"/jvm/f",
	}, 2)
	if !meta.JavaCacertsTruncated {
		t.Fatal("expected truncated=true")
	}
	if meta.JavaCacertsJvmTotal != 6 {
		t.Fatalf("expected total 6, got %d", meta.JavaCacertsJvmTotal)
	}
	if meta.JavaCacertsJvmScanned != 2 || len(homes) != 2 {
		t.Fatalf("expected 2 scanned homes, got scanned=%d homes=%d", meta.JavaCacertsJvmScanned, len(homes))
	}
	if homes[0] != "/jvm/a" || homes[1] != "/jvm/b" {
		t.Fatalf("expected sorted capped homes, got %v", homes)
	}
}

func TestNormalizeKeytoolFingerprint(t *testing.T) {
	got := normalizeKeytoolFingerprint("1C:F8:43:14:7E:D4:08:6A:D3:97:17:CC:C6:A3:AA:8D:2B:E6:8C:B9:01:81:6E:C7:FE:BA:0E:3D:ED:86:44:93")
	if got != keytoolSampleThumbprint1 {
		t.Fatalf("unexpected normalized fingerprint: %q", got)
	}
}

func TestResolveJavaStorePassword(t *testing.T) {
	t.Setenv("JAVA_CACERTS_PASSWORD", "from-env")
	if got := resolveJavaStorePassword("configured"); got != "configured" {
		t.Fatalf("expected configured password, got %q", got)
	}
	if got := resolveJavaStorePassword(""); got != "from-env" {
		t.Fatalf("expected env password, got %q", got)
	}
	t.Setenv("JAVA_CACERTS_PASSWORD", "")
	if got := resolveJavaStorePassword(""); got != defaultJavaStorePass {
		t.Fatalf("expected default password, got %q", got)
	}
}

func TestResolveJavaHomesFromJavaHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("JAVA_HOME", home)

	homes := resolveJavaHomes()
	if len(homes) != 1 || homes[0] != home {
		t.Fatalf("expected single JAVA_HOME entry %q, got %v", home, homes)
	}
}

func TestParseKeytoolNotAfterRFC3339(t *testing.T) {
	got := parseKeytoolNotAfter("2026-06-15T12:00:00Z")
	if got != "2026-06-15T12:00:00Z" {
		t.Fatalf("unexpected RFC3339 parse: %q", got)
	}
}
