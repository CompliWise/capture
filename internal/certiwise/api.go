package certiwise

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	enrollPath          = "/api/v1/agent/enroll"
	heartbeatPath       = "/api/v1/agent/heartbeat"
	upgradeArtifactPath = "/api/v1/agent/upgrade-artifact"
)

// EnrollRequest is the body for POST /api/v1/agent/enroll.
type EnrollRequest struct {
	EnrollmentCode  string `json:"enrollmentCode"`
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	AgentVersion    string `json:"agentVersion"`
	HostFingerprint string `json:"hostFingerprint,omitempty"`
}

// EnrollResponse is returned after a successful enrollment exchange.
type EnrollResponse struct {
	AgentID             string `json:"agentId"`
	OrganizationID      string `json:"organizationId"`
	Token               string `json:"token"`
	PollIntervalSeconds int    `json:"pollIntervalSeconds"`
}

// HeartbeatRequest is the body for POST /api/v1/agent/heartbeat.
type HeartbeatRequest struct {
	AgentVersion  string `json:"agentVersion"`
	Hostname      string `json:"hostname,omitempty"`
	Platform      string `json:"platform,omitempty"`
	UpgradeStatus string `json:"upgradeStatus,omitempty"`
	LastUpgradeAt string `json:"lastUpgradeAt,omitempty"`
	UpgradeError  string `json:"upgradeError,omitempty"`
}

// HeartbeatUpgradeDirective tells the agent whether to upgrade.
type HeartbeatUpgradeDirective struct {
	TargetVersion        string `json:"targetVersion"`
	MaintenanceWindowUTC string `json:"maintenanceWindowUtc"`
	Force                bool   `json:"force"`
}

// HeartbeatResponse is returned after a successful heartbeat.
type HeartbeatResponse struct {
	LastHeartbeatAt string                     `json:"lastHeartbeatAt"`
	Status          string                     `json:"status"`
	Upgrade         *HeartbeatUpgradeDirective `json:"upgrade"`
}

// UpgradeArtifactResponse is returned by GET /api/v1/agent/upgrade-artifact.
type UpgradeArtifactResponse struct {
	DownloadURL string `json:"downloadUrl"`
	SHA256      string `json:"sha256"`
	ExpiresAt   string `json:"expiresAt"`
}

type apiError struct {
	Message string `json:"message"`
}

// SetToken updates the bearer token used for authenticated API calls.
func (c *Client) SetToken(token string) {
	c.token = token
}

// Enroll exchanges a one-time enrollment code for an agent token.
func (c *Client) Enroll(req EnrollRequest) (*EnrollResponse, error) {
	var resp EnrollResponse
	if err := c.doJSON(http.MethodPost, enrollPath, req, false, &resp); err != nil {
		return nil, err
	}
	if resp.Token == "" {
		return nil, fmt.Errorf("enroll response missing token")
	}
	c.token = resp.Token
	return &resp, nil
}

// Heartbeat reports agent liveness to the CompliWise API.
func (c *Client) Heartbeat(req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.doJSON(http.MethodPost, heartbeatPath, req, true, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetUpgradeArtifact fetches a signed download URL for the target release.
func (c *Client) GetUpgradeArtifact(ctx context.Context, targetVersion, platform string) (*UpgradeArtifactResponse, error) {
	query := url.Values{}
	query.Set("targetVersion", targetVersion)
	query.Set("platform", platform)
	path := upgradeArtifactPath + "?" + query.Encode()

	var resp UpgradeArtifactResponse
	if err := c.doJSONWithContext(ctx, http.MethodGet, path, nil, true, &resp, nil); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) doJSON(method, path string, body any, auth bool, dest any) error {
	return c.doJSONWithContext(context.Background(), method, path, body, auth, dest, nil)
}

func (c *Client) doJSONWithContext(
	ctx context.Context,
	method,
	path string,
	body any,
	auth bool,
	dest any,
	extraHeaders map[string]string,
) error {
	_, _, err := c.doJSONWithContextStatus(ctx, method, path, body, auth, dest, extraHeaders)
	return err
}

func (c *Client) doJSONWithContextStatus(
	ctx context.Context,
	method,
	path string,
	body any,
	auth bool,
	dest any,
	extraHeaders map[string]string,
) (int, string, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, "", fmt.Errorf("marshal request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return 0, "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if auth {
		if c.token == "" {
			return 0, "", fmt.Errorf("agent token is required")
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		if c.mtlsFingerprint != "" {
			req.Header.Set("x-mtls-cert-fingerprint", c.mtlsFingerprint)
		}
	}
	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, resp.Header.Get("ETag"), nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if dest == nil {
			return resp.StatusCode, resp.Header.Get("ETag"), nil
		}
		if err := json.Unmarshal(responseBody, dest); err != nil {
			return resp.StatusCode, "", fmt.Errorf("decode response: %w", err)
		}
		return resp.StatusCode, resp.Header.Get("ETag"), nil
	}

	var apiErr apiError
	if err := json.Unmarshal(responseBody, &apiErr); err == nil && apiErr.Message != "" {
		return resp.StatusCode, "", fmt.Errorf("%s %s: %s", method, path, apiErr.Message)
	}

	snippet := strings.TrimSpace(string(responseBody))
	if len(snippet) > 256 {
		snippet = snippet[:256] + "..."
	}
	return resp.StatusCode, "", fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, snippet)
}
