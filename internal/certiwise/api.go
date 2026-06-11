package certiwise

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	enrollPath    = "/api/v1/agent/enroll"
	heartbeatPath = "/api/v1/agent/heartbeat"
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
	AgentVersion string `json:"agentVersion"`
	Hostname     string `json:"hostname,omitempty"`
	Platform     string `json:"platform,omitempty"`
}

// HeartbeatResponse is returned after a successful heartbeat.
type HeartbeatResponse struct {
	LastHeartbeatAt string `json:"lastHeartbeatAt"`
	Status          string `json:"status"`
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

func (c *Client) doJSON(method, path string, body any, auth bool, dest any) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.baseURL+path, payload)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if auth {
		if c.token == "" {
			return fmt.Errorf("agent token is required")
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if dest == nil {
			return nil
		}
		if err := json.Unmarshal(responseBody, dest); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	}

	var apiErr apiError
	if err := json.Unmarshal(responseBody, &apiErr); err == nil && apiErr.Message != "" {
		return fmt.Errorf("%s %s: %s", method, path, apiErr.Message)
	}

	snippet := strings.TrimSpace(string(responseBody))
	if len(snippet) > 256 {
		snippet = snippet[:256] + "..."
	}
	return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, snippet)
}
