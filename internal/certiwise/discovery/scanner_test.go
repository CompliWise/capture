package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleThumbprint = "1cf843147ed4086ad39717ccc6a3aa8d2be68cb901816ec7feba0e3ded864493"

func TestParseSampleCAPEM(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "sample-ca.pem"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	cert, err := parseCertificatePEM(data)
	if err != nil {
		t.Fatalf("parseCertificatePEM: %v", err)
	}

	item := certToItem(cert, "linux_system_ca", "/tmp/sample.pem", "", "linux_update_ca_certificates")
	if item.Thumbprint != sampleThumbprint {
		t.Fatalf("expected thumbprint %s, got %s", sampleThumbprint, item.Thumbprint)
	}
	if item.SubjectCN != "CompliWise E2E Root CA" {
		t.Fatalf("expected subject CN, got %q", item.SubjectCN)
	}
}

func TestScanPEMGlobInTempDir(t *testing.T) {
	dir := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("testdata", "sample-ca.pem"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.pem"), fixture, 0o644); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	items := ScanPEMGlob([]string{dir}, 10)
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Source != "pem_directory" {
		t.Fatalf("expected pem_directory source, got %q", items[0].Source)
	}
}

func TestScanMergeDedupeAndCap(t *testing.T) {
	dir := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("testdata", "sample-ca.pem"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dup.pem"), fixture, 0o644); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dup.crt"), fixture, 0o644); err != nil {
		t.Fatalf("write crt: %v", err)
	}

	items := Scan(ScanOptions{
		PemPaths: []string{dir},
		MaxItems: 1,
	})
	if len(items) != 1 {
		t.Fatalf("expected cap of 1 item, got %d", len(items))
	}
}

func TestOnDemandDue(t *testing.T) {
	if !OnDemandDue("2026-06-13T10:00:00Z", "") {
		t.Fatal("expected on-demand when last scan missing")
	}
	if !OnDemandDue("2026-06-13T10:00:00Z", "2026-06-13T08:00:00Z") {
		t.Fatal("expected on-demand when request is newer")
	}
	if OnDemandDue("2026-06-13T08:00:00Z", "2026-06-13T10:00:00Z") {
		t.Fatal("expected no on-demand when request is older")
	}
}
