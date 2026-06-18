package certiwise

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPullAssignmentsUsesIfNoneMatchAndHandles304(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count == 1 {
			w.Header().Set("ETag", `W/"sha256:first"`)
			_ = json.NewEncoder(w).Encode(AssignmentsPullResponse{
				Etag:        "sha256:first",
				ConfigEtag:  "sha256:cfg",
				Assignments: []AssignmentPullItem{},
			})
			return
		}

		if r.Header.Get("If-None-Match") != `W/"sha256:first"` {
			t.Fatalf("expected If-None-Match header, got %q", r.Header.Get("If-None-Match"))
		}
		w.Header().Set("ETag", `W/"sha256:first"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    server.URL,
		AgentToken: "token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	first, err := client.PullAssignments()
	if err != nil {
		t.Fatalf("first PullAssignments: %v", err)
	}
	if first.Etag != "sha256:first" {
		t.Fatalf("expected first etag, got %q", first.Etag)
	}

	second, err := client.PullAssignments()
	if err != nil {
		t.Fatalf("second PullAssignments: %v", err)
	}
	if second.Etag != "sha256:first" {
		t.Fatalf("expected cached etag on 304, got %q", second.Etag)
	}
	if requestCount.Load() != 2 {
		t.Fatalf("expected 2 requests, got %d", requestCount.Load())
	}
}
