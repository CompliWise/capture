package probe

import (
	"net/url"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/certiwise"
)

func TestParseProbeURL(t *testing.T) {
	target, err := ParseProbeURL("https://payment-api.internal:8443/health")
	if err != nil {
		t.Fatalf("ParseProbeURL: %v", err)
	}
	if target.Host != "payment-api.internal" || target.Port != 8443 {
		t.Fatalf("unexpected target: %+v", target)
	}
	if target.ServerName != "payment-api.internal" {
		t.Fatalf("expected server name from host, got %q", target.ServerName)
	}
}

func TestResolveTargetsDedupesEnvAndAssignments(t *testing.T) {
	targets, err := ResolveTargets(
		[]string{"https://e2e-probe:443/", "https://e2e-probe:443/extra"},
		[]certiwise.AssignmentPullItem{
			{
				ApplicationID: "app-1",
				Config: certiwise.AssignmentConfig{
					VerifyEndpoint:   "https://e2e-probe:443/",
					VerifyServerName: "e2e-probe",
				},
			},
			{
				ApplicationID: "app-2",
				Config: certiwise.AssignmentConfig{
					VerifyEndpoint: "https://other.example:443/",
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("ResolveTargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 unique targets, got %d", len(targets))
	}
}

func TestTargetFromAssignmentUsesVerifyServerName(t *testing.T) {
	target, ok := TargetFromAssignment(certiwise.AssignmentPullItem{
		DeploymentID:  "dep-1",
		ApplicationID: "app-1",
		Config: certiwise.AssignmentConfig{
			VerifyEndpoint:   "https://api.example.com:8443/health",
			VerifyServerName: "api.example.com",
		},
	})
	if !ok {
		t.Fatal("expected assignment target")
	}
	if target.ServerName != "api.example.com" {
		t.Fatalf("expected verify server name, got %q", target.ServerName)
	}
	if target.DeploymentID != "dep-1" {
		t.Fatalf("expected deployment id, got %q", target.DeploymentID)
	}
}

func TestParseProbeURLRejectsNonHTTPS(t *testing.T) {
	_, err := ParseProbeURL("http://insecure.example:8080/")
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("expected scheme error, got %v", err)
	}
}

func TestParseProbeURLFromAssignmentHost(t *testing.T) {
	parsed, err := url.Parse("https://compliwise-e2e-probe:443/")
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}
	if parsed.Hostname() != "compliwise-e2e-probe" {
		t.Fatalf("unexpected host: %q", parsed.Hostname())
	}
}
