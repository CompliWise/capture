package dotnet

import (
	"strings"
	"testing"
)

func TestResolveBundlePathValid(t *testing.T) {
	path, err := ResolveBundlePath("/etc/compliwise/dotnet/trust.pem")
	if err != nil {
		t.Fatalf("ResolveBundlePath: %v", err)
	}
	if path != "/etc/compliwise/dotnet/trust.pem" {
		t.Fatalf("expected absolute bundle path, got %q", path)
	}
}

func TestResolveBundlePathRejectsEmpty(t *testing.T) {
	_, err := ResolveBundlePath("")
	if err == nil {
		t.Fatal("expected error for empty trust store path")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required error, got %v", err)
	}
}

func TestResolveBundlePathRejectsTraversal(t *testing.T) {
	_, err := ResolveBundlePath("/etc/compliwise/../secret/ca.pem")
	if err == nil {
		t.Fatal("expected path traversal rejection")
	}
	if !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("expected traversal error, got %v", err)
	}
}
