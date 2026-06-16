package node

import (
	"strings"
	"testing"
)

func TestResolveTrustStorePathDefault(t *testing.T) {
	if got := ResolveTrustStorePath(""); got != DefaultTrustStorePath {
		t.Fatalf("expected default %q, got %q", DefaultTrustStorePath, got)
	}
}

func TestResolveTrustStorePathExplicit(t *testing.T) {
	if got := ResolveTrustStorePath("/custom/ca"); got != "/custom/ca" {
		t.Fatalf("expected explicit path, got %q", got)
	}
}

func TestBundlePathUsesAlias(t *testing.T) {
	path, err := BundlePath("/etc/compliwise/ca-bundles", "assign-1", "webhook-dispatcher")
	if err != nil {
		t.Fatalf("bundle path: %v", err)
	}
	want := "/etc/compliwise/ca-bundles/compliwise-webhook-dispatcher.pem"
	if path != want {
		t.Fatalf("expected %q, got %q", want, path)
	}
}

func TestBundlePathFallsBackToAssignmentID(t *testing.T) {
	path, err := BundlePath("/tmp/node-ca", "assign-node", "")
	if err != nil {
		t.Fatalf("bundle path: %v", err)
	}
	want := "/tmp/node-ca/compliwise-compliwise-assign-node.pem"
	if path != want {
		t.Fatalf("expected %q, got %q", want, path)
	}
}

func TestBundlePathRejectsTraversal(t *testing.T) {
	_, err := BundlePath("/tmp/base", "assign-1", "../secret")
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Fatalf("expected path error, got %v", err)
	}
}
