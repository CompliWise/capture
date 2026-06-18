package synthetic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunCheckStatusUp(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := RunCheck(context.Background(), Monitor{
		URL:       server.URL,
		TimeoutMs: 5000,
		Assertions: Assertions{
			ExpectHTTPStatus: http.StatusOK,
		},
	}, "CompliWise-Capture-Agent/test")

	if result.Status != StatusUp {
		t.Fatalf("expected up, got %q (%s)", result.Status, result.ErrorMessage)
	}
	if result.HTTPStatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", result.HTTPStatusCode)
	}
}

func TestRunCheckHttpStatusDown(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	result := RunCheck(context.Background(), Monitor{
		URL:       server.URL,
		TimeoutMs: 5000,
		Assertions: Assertions{
			ExpectHTTPStatus: http.StatusOK,
		},
	}, "CompliWise-Capture-Agent/test")

	if result.Status != StatusDown {
		t.Fatalf("expected down, got %q", result.Status)
	}
}

func TestRunCheckSlowResponseDegraded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(120 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := RunCheck(context.Background(), Monitor{
		URL:       server.URL,
		TimeoutMs: 5000,
		Assertions: Assertions{
			ExpectHTTPStatus:  http.StatusOK,
			MaxResponseTimeMs: 50,
		},
	}, "CompliWise-Capture-Agent/test")

	if result.Status != StatusDegraded {
		t.Fatalf("expected degraded, got %q (%s)", result.Status, result.ErrorMessage)
	}
}

func TestEvaluateAssertionsCertExpiryDegraded(t *testing.T) {
	failures := evaluateAssertions(
		Monitor{
			Assertions: Assertions{
				MaxDaysUntilExpiry: 30,
			},
		},
		CheckResult{
			CertDaysRemaining: 5,
			CertExpiresAt:     time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339),
		},
		nil,
		0,
	)
	if len(failures) == 0 {
		t.Fatal("expected cert expiry assertion failure")
	}
	if worstStatus(failures) != StatusDegraded {
		t.Fatalf("expected degraded, got %q", worstStatus(failures))
	}
}

func TestWorstStatusAggregation(t *testing.T) {
	messages := []string{
		"HTTP status 503 does not match expected 200",
		"response time 500ms exceeds max 100ms",
	}
	if got := worstStatus(messages); got != StatusDown {
		t.Fatalf("expected down when mixed failures, got %q", got)
	}
}
