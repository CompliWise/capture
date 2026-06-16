package python

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBundlePathExplicit(t *testing.T) {
	path, err := ResolveBundlePath("/custom/cacert.pem", "/venv")
	if err != nil {
		t.Fatalf("ResolveBundlePath: %v", err)
	}
	if path != "/custom/cacert.pem" {
		t.Fatalf("expected explicit path, got %q", path)
	}
}

func TestResolveBundlePathVenvSitePackages(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "lib", "python3.12", "site-packages", "certifi", "cacert.pem")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(bundlePath, []byte("bundle\n"), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	path, err := ResolveBundlePath("", dir)
	if err != nil {
		t.Fatalf("ResolveBundlePath: %v", err)
	}
	if path != bundlePath {
		t.Fatalf("expected %q, got %q", bundlePath, path)
	}
}

func TestResolveBundlePathVenvPython(t *testing.T) {
	dir := t.TempDir()
	venvPython := filepath.Join(dir, "bin", "python")
	if err := os.MkdirAll(filepath.Dir(venvPython), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(venvPython, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write python stub: %v", err)
	}

	original := certifiRunner
	t.Cleanup(func() { certifiRunner = original })
	certifiRunner = func(python string) (string, error) {
		if python != venvPython {
			t.Fatalf("expected venv python %q, got %q", venvPython, python)
		}
		return "/venv/certifi/cacert.pem", nil
	}

	path, err := ResolveBundlePath("", dir)
	if err != nil {
		t.Fatalf("ResolveBundlePath: %v", err)
	}
	if path != "/venv/certifi/cacert.pem" {
		t.Fatalf("unexpected path %q", path)
	}
}

func TestCertifiPathFromVenvMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := CertifiPathFromVenv(dir); err == nil {
		t.Fatal("expected error when certifi missing in venv")
	}
}
