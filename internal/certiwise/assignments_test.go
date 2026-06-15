package certiwise

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPullAssignmentsConditional304(t *testing.T) {
	t.Parallel()

	var requestCount int
	var sawIfNoneMatch bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != assignmentsPath {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Fatal("expected bearer authorization")
		}

		ifNoneMatch := r.Header.Get("If-None-Match")
		if ifNoneMatch != "" {
			sawIfNoneMatch = true
			w.Header().Set("ETag", `W/"sha256:unchanged"`)
			w.Header().Set("Cache-Control", "private, no-cache")
			w.WriteHeader(http.StatusNotModified)
			return
		}

		body := AssignmentsPullResponse{
			Etag:         "sha256:first",
			ConfigEtag:   "sha256:cfg",
			Assignments:  []AssignmentPullItem{},
		}
		w.Header().Set("ETag", `W/"sha256:unchanged"`)
		w.Header().Set("Cache-Control", "private, no-cache")
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{BaseURL: server.URL, AgentToken: "token"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	first, err := client.PullAssignments()
	if err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if first.Etag != "sha256:first" {
		t.Fatalf("expected first etag, got %q", first.Etag)
	}

	second, err := client.PullAssignments()
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if second == nil {
		t.Fatal("expected cached pull on 304")
	}
	if requestCount != 2 {
		t.Fatalf("expected 2 requests, got %d", requestCount)
	}
	if !sawIfNoneMatch {
		t.Fatal("expected If-None-Match on second request")
	}
}
