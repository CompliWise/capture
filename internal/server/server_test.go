package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/compliwise/capture/internal/config"
	"github.com/compliwise/capture/internal/server/handler"
	"github.com/gin-gonic/gin"
)

func testHandler() http.Handler {
	gin.SetMode(gin.TestMode)
	return InitializeHandler(&config.Config{APISecret: "secret"}, &handler.CaptureMeta{Version: "test"})
}

func TestUnsupportedMethodReturns405(t *testing.T) {
	h := testHandler()

	tests := []struct {
		method string
		path   string
		allow  string
	}{
		{http.MethodTrace, "/health", "GET"},
		{http.MethodPut, "/health", "GET"},
		{http.MethodTrace, "/api/v1/metrics", "GET"},
		{http.MethodTrace, "/api/v1/metrics/cpu", "GET"},
		{http.MethodPatch, "/api/v1/certiwise/probe", "POST"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer secret")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
			}
			allow := rec.Header().Get("Allow")
			if allow != tt.allow {
				t.Fatalf("Allow = %q, want %q", allow, tt.allow)
			}
		})
	}
}

func TestUnknownPathStillReturns404(t *testing.T) {
	h := testHandler()
	req := httptest.NewRequest(http.MethodTrace, "/does-not-exist", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHealthGETStillSucceeds(t *testing.T) {
	h := testHandler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "OK") {
		t.Fatalf("body = %q, want to contain OK", rec.Body.String())
	}
}
