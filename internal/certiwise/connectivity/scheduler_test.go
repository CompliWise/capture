package connectivity

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

func TestSchedulerSkipsWhenFlagFalse(t *testing.T) {
	var submitCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/connectivity-test" {
			submitCount.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := certiwise.NewClient(certiwise.ClientConfig{
		BaseURL:    server.URL,
		AgentToken: "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	scheduler := NewScheduler()
	err = scheduler.RunIfRequested(
		context.Background(),
		client,
		&cwconfig.Config{APIURL: server.URL},
		&certiwise.AssignmentsPullResponse{},
	)
	if err != nil {
		t.Fatalf("RunIfRequested: %v", err)
	}
	if submitCount.Load() != 0 {
		t.Fatalf("expected no submit, got %d", submitCount.Load())
	}
}

func TestSchedulerSubmitsWhenFlagTrue(t *testing.T) {
	var submitCount atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/assignments":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(certiwise.AssignmentsPullResponse{})
		case "/api/v1/agent/connectivity-test":
			submitCount.Add(1)
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				Steps []certiwise.ConnectivityTestStep `json:"steps"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode submit body: %v", err)
			}
			if len(payload.Steps) != 4 {
				t.Fatalf("expected 4 steps in submit payload, got %d", len(payload.Steps))
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
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

	scheduler := NewScheduler()
	err = scheduler.RunIfRequested(
		context.Background(),
		client,
		&cwconfig.Config{
			APIURL:             server.URL,
			InsecureSkipVerify: true,
		},
		&certiwise.AssignmentsPullResponse{ConnectivityTestRequested: true},
	)
	if err != nil {
		t.Fatalf("RunIfRequested: %v", err)
	}
	if submitCount.Load() != 1 {
		t.Fatalf("expected one submit, got %d", submitCount.Load())
	}
}
