package certiwise

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	assignmentsPath = "/api/v1/agent/assignments"
)

// AssignmentConfig mirrors durable assignment configuration from the API.
type AssignmentConfig struct {
	Alias            string   `json:"alias,omitempty"`
	AutoRenew        *bool    `json:"autoRenew,omitempty"`
	RemoveOnRevoke   *bool    `json:"removeOnRevoke,omitempty"`
	VerifyEndpoint   string   `json:"verifyEndpoint,omitempty"`
	VerifyServerName string   `json:"verifyServerName,omitempty"`
	TrustStorePath    string   `json:"trustStorePath,omitempty"`
	KeychainPath      string   `json:"keychainPath,omitempty"`
	StorePasswordRef  string   `json:"storePasswordRef,omitempty"`
	JavaHome          string   `json:"javaHome,omitempty"`
	PythonVenvPath    string   `json:"pythonVenvPath,omitempty"`
	ReloadCommand     []string `json:"reloadCommand,omitempty"`
	CertFileName     string   `json:"certFileName,omitempty"`
	KeyFileName      string   `json:"keyFileName,omitempty"`
	KeyPermissionMode string  `json:"keyPermissionMode,omitempty"`
	EnvFilePath      string   `json:"envFilePath,omitempty"`
	UseOpensslCa     bool     `json:"useOpensslCa,omitempty"`
	NodeFlags        []string `json:"nodeFlags,omitempty"`
	PreferOsStore    bool     `json:"preferOsStore,omitempty"`
	DbUser           string   `json:"dbUser,omitempty"`
	RacfProfile      string   `json:"racfProfile,omitempty"`
	SystemId         string   `json:"systemId,omitempty"`
	GatewayMode      bool     `json:"gatewayMode,omitempty"`
	StoreLocation    string   `json:"storeLocation,omitempty"`
	StoreName        string   `json:"storeName,omitempty"`
	IIS              *IISAssignmentConfig `json:"iis,omitempty"`
}

// IISAssignmentConfig configures IIS HTTPS binding for Windows server identity.
type IISAssignmentConfig struct {
	SiteName     string `json:"siteName"`
	BindingHost  string `json:"bindingHost,omitempty"`
	BindingPort  int    `json:"bindingPort,omitempty"`
	IPAddress    string `json:"ipAddress,omitempty"`
	SNI          bool   `json:"sni,omitempty"`
}

// AssignmentMaterial is ephemeral PEM material returned on agent pull.
type AssignmentMaterial struct {
	ChainPem      string `json:"chainPem"`
	PrivateKeyPem string `json:"privateKeyPem,omitempty"`
}

// AssignmentPullItem is one assignment entry returned by GET /agent/assignments.
type AssignmentPullItem struct {
	AssignmentID      string             `json:"assignmentId"`
	DeploymentID      string             `json:"deploymentId"`
	ApplicationID     string             `json:"applicationId"`
	CertificateID     string             `json:"certificateId"`
	Version           int                `json:"version"`
	TrustStoreType    string             `json:"trustStoreType"`
	MaterialType      string             `json:"materialType"`
	IncludePrivateKey bool               `json:"includePrivateKey"`
	Config            AssignmentConfig   `json:"config"`
	Material          AssignmentMaterial `json:"material"`
	DeploymentIntent  string             `json:"deploymentIntent,omitempty"`
}

// AgentPullConfig is remote runtime configuration from GET /agent/assignments.
type AgentPullConfig struct {
	PollIntervalSeconds      int  `json:"pollIntervalSeconds"`
	HeartbeatIntervalSeconds int  `json:"heartbeatIntervalSeconds"`
	TelemetryBatchSize       int  `json:"telemetryBatchSize,omitempty"`
	TelemetryFlushSeconds    int  `json:"telemetryFlushSeconds,omitempty"`
	Enabled                  bool `json:"enabled"`
}

// AssignmentsPullResponse is the body of GET /agent/assignments.
type AssignmentsPullResponse struct {
	Etag                     string               `json:"etag"`
	ConfigEtag               string               `json:"configEtag"`
	Config                   AgentPullConfig      `json:"config"`
	Assignments              []AssignmentPullItem `json:"assignments"`
	ConnectivityTestRequested bool                `json:"connectivityTestRequested"`
	DiscoveryScanRequestedAt *string              `json:"discoveryScanRequestedAt"`
	LastDiscoveryScanAt      *string              `json:"lastDiscoveryScanAt"`
}

// DiscoveryRequestedAt returns the on-demand scan request timestamp, if any.
func (r *AssignmentsPullResponse) DiscoveryRequestedAt() string {
	return optionalString(r.DiscoveryScanRequestedAt)
}

// LastDiscoveryAt returns the last ingested discovery scan timestamp, if any.
func (r *AssignmentsPullResponse) LastDiscoveryAt() string {
	return optionalString(r.LastDiscoveryScanAt)
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// DeploymentReportRequest is the body for POST /agent/deployments/:id/report.
type DeploymentReportRequest struct {
	Status       string `json:"status"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	InstallerLog string `json:"installerLog,omitempty"`
	FinishedAt   string `json:"finishedAt"`
}

// PullAssignments fetches pending assignment work for this agent.
func (c *Client) PullAssignments() (*AssignmentsPullResponse, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+assignmentsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if err := c.SetAuthHeaders(req); err != nil {
		return nil, err
	}
	if c.assignmentsEtag != "" {
		req.Header.Set("If-None-Match", c.assignmentsEtag)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", assignmentsPath, err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotModified {
		slog.Debug("assignments unchanged (304)")
		if c.cachedAssignmentsPull != nil {
			return c.cachedAssignmentsPull, nil
		}
		etag := strings.TrimSpace(resp.Header.Get("ETag"))
		if etag == "" {
			etag = c.assignmentsEtag
		}
		return &AssignmentsPullResponse{Etag: etag}, nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var pull AssignmentsPullResponse
		if err := json.Unmarshal(responseBody, &pull); err != nil {
			return nil, fmt.Errorf("decode assignments response: %w", err)
		}
		if headerEtag := strings.TrimSpace(resp.Header.Get("ETag")); headerEtag != "" {
			c.assignmentsEtag = headerEtag
		} else if pull.Etag != "" {
			c.assignmentsEtag = pull.Etag
		}
		c.cachedAssignmentsPull = &pull
		return &pull, nil
	}

	var apiErr apiError
	if err := json.Unmarshal(responseBody, &apiErr); err == nil && apiErr.Message != "" {
		return nil, fmt.Errorf("GET %s: %s", assignmentsPath, apiErr.Message)
	}

	snippet := strings.TrimSpace(string(responseBody))
	if len(snippet) > 256 {
		snippet = snippet[:256] + "..."
	}
	return nil, fmt.Errorf("GET %s: status %d: %s", assignmentsPath, resp.StatusCode, snippet)
}

// ReportDeployment posts install progress back to the control plane.
func (c *Client) ReportDeployment(deploymentID string, req DeploymentReportRequest) error {
	path := fmt.Sprintf("/api/v1/agent/deployments/%s/report", deploymentID)
	return c.doJSON(http.MethodPost, path, req, true, nil)
}

// NowISO returns the current time in RFC3339 format.
func NowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}
