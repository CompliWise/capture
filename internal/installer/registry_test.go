package installer

import (
	"context"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/installer/testfixtures"
)

func TestThumbprintFromPEM(t *testing.T) {
	thumbprint, err := ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("ThumbprintFromPEM: %v", err)
	}
	if len(thumbprint) != 64 {
		t.Fatalf("expected 64-char thumbprint, got %q", thumbprint)
	}
}

func TestTruncateLog(t *testing.T) {
	long := strings.Repeat("a", MaxInstallerLogBytes+10)
	if len(TruncateLog(long)) != MaxInstallerLogBytes {
		t.Fatalf("expected truncated log length %d", MaxInstallerLogBytes)
	}
}

func TestValidatePathWithinBaseRejectsTraversal(t *testing.T) {
	if err := ValidatePathWithinBase("/tmp/base", "/tmp/base/../secret"); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestRegistryLookupBySupports(t *testing.T) {
	registry := NewRegistry()
	registry.installers["custom_type"] = stubInstaller{}

	inst, ok := registry.Lookup("custom_type")
	if !ok {
		t.Fatal("expected custom installer")
	}
	if !inst.Supports("trust_anchor", "custom_type") {
		t.Fatal("expected trust_anchor support")
	}
}

type stubInstaller struct{}

func (stubInstaller) Install(_ context.Context, _ InstallOptions) (string, error) {
	return "ok", nil
}

func (stubInstaller) Remove(_ context.Context, _ RemoveOptions) (string, error) {
	return "ok", nil
}

func (stubInstaller) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "custom_type"
}
