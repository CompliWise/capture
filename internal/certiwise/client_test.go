package certiwise

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNewClientUsesProxyFromEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")

	client, err := NewClient(ClientConfig{
		BaseURL:    "https://api.example.com",
		AgentToken: "token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	proxyURL, err := client.httpClient.Transport.(*http.Transport).Proxy(req)
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if proxyURL == nil || proxyURL.Host != "127.0.0.1:9" {
		t.Fatalf("expected HTTPS_PROXY, got %v", proxyURL)
	}
}

func TestNewClientFromEnvRequiresBaseURL(t *testing.T) {
	os.Unsetenv("COMPLIWISE_API_URL")
	if _, err := NewClientFromEnv(); err == nil {
		t.Fatal("expected error when COMPLIWISE_API_URL missing")
	}
}

func TestClientCanReachServerWithCustomTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:            server.URL,
		AgentToken:         "token",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, err := client.httpClient.Get(server.URL + "/api/v1/agent/assignments")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 proving path, got %d", resp.StatusCode)
	}
}
