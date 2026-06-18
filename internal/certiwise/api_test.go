package certiwise

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollAndHeartbeat(t *testing.T) {
	var token string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case enrollPath:
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST enroll, got %s", r.Method)
			}
			var body EnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode enroll body: %v", err)
			}
			if body.EnrollmentCode == "" {
				http.Error(w, `{"message":"missing code"}`, http.StatusBadRequest)
				return
			}
			token = "cw_agent_test_token_123456789012345678901234567890"
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(EnrollResponse{
				AgentID:             "agent_test",
				OrganizationID:      "org_test",
				Token:               token,
				PollIntervalSeconds: 60,
			})
		case heartbeatPath:
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST heartbeat, got %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer "+token {
				t.Fatalf("expected bearer token, got %q", got)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(HeartbeatResponse{
				LastHeartbeatAt: "2026-06-10T19:40:17.444+00:00",
				Status:          "online",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{BaseURL: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	enrollResp, err := client.Enroll(EnrollRequest{
		EnrollmentCode: "cw_enroll_test_code_123456789012345678901234567890",
		Hostname:       "payment-agent",
		Platform:       "linux/amd64",
		AgentVersion:   "develop",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrollResp.Token != token {
		t.Fatalf("expected token %q, got %q", token, enrollResp.Token)
	}

	heartbeatResp, err := client.Heartbeat(HeartbeatRequest{
		AgentVersion: "develop",
		Hostname:     "payment-agent",
		Platform:     "linux/amd64",
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if heartbeatResp.Status != "online" {
		t.Fatalf("expected online status, got %q", heartbeatResp.Status)
	}
}
