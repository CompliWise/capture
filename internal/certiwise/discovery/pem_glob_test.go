package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanPEMGlobMixedExtensions(t *testing.T) {
	dir := t.TempDir()
	sample, err := os.ReadFile("testdata/sample-ca.pem")
	if err != nil {
		t.Fatalf("read sample pem: %v", err)
	}

	for _, name := range []string{"cert.pem", "cert.crt", "cert.cer"} {
		if err := os.WriteFile(filepath.Join(dir, name), sample, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	items := ScanPEMGlob([]string{dir}, 10)
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
}
