package connectivity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

func TestRunProbeAllStepsPass(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/assignments" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(certiwise.AssignmentsPullResponse{
			Etag:       "etag-1",
			ConfigEtag: "config-1",
		})
	}))
	defer server.Close()

	client, err := certiwise.NewClient(certiwise.ClientConfig{
		BaseURL:            server.URL,
		AgentToken:         "test-token",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cfg := &cwconfig.Config{
		APIURL:             server.URL,
		InsecureSkipVerify: true,
	}

	steps := RunProbe(context.Background(), cfg, client)
	if len(steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(steps))
	}

	for _, step := range steps {
		if !step.Passed {
			t.Fatalf("expected step %q to pass, got message %q", step.Step, step.Message)
		}
		if step.DurationMs < 0 {
			t.Fatalf("expected non-negative duration for %q", step.Step)
		}
	}
}

func TestRunProbeDNSFailure(t *testing.T) {
	client, err := certiwise.NewClient(certiwise.ClientConfig{
		BaseURL:            "https://invalid.invalid.invalid",
		AgentToken:         "test-token",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cfg := &cwconfig.Config{
		APIURL:             "https://invalid.invalid.invalid",
		InsecureSkipVerify: true,
	}

	steps := RunProbe(context.Background(), cfg, client)
	if len(steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(steps))
	}
	if steps[0].Step != StepDNSResolve || steps[0].Passed {
		t.Fatalf("expected failed dns_resolve, got %+v", steps[0])
	}
}

func TestRunProbeInvalidBaseURL(t *testing.T) {
	steps := RunProbe(context.Background(), &cwconfig.Config{APIURL: "://missing-host"}, nil)
	if len(steps) != 4 {
		t.Fatalf("expected 4 steps, got %d", len(steps))
	}
	for _, step := range steps {
		if step.Passed {
			t.Fatalf("expected all steps to fail for invalid base URL, step %q passed", step.Step)
		}
	}
}
