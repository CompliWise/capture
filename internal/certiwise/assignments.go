package certiwise

import (
	"fmt"
	"net/http"
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
	TrustStorePath   string   `json:"trustStorePath,omitempty"`
	ReloadCommand    []string `json:"reloadCommand,omitempty"`
	CertFileName     string   `json:"certFileName,omitempty"`
}

// TrustAnchorMaterial is ephemeral PEM material for trust-anchor installs.
type TrustAnchorMaterial struct {
	ChainPem string `json:"chainPem"`
}

// AssignmentPullItem is one assignment entry returned by GET /agent/assignments.
type AssignmentPullItem struct {
	AssignmentID    string              `json:"assignmentId"`
	DeploymentID      string              `json:"deploymentId"`
	ApplicationID     string              `json:"applicationId"`
	CertificateID     string              `json:"certificateId"`
	Version           int                 `json:"version"`
	TrustStoreType    string              `json:"trustStoreType"`
	MaterialType      string              `json:"materialType"`
	IncludePrivateKey bool                `json:"includePrivateKey"`
	Config            AssignmentConfig    `json:"config"`
	Material          TrustAnchorMaterial `json:"material"`
}

// AssignmentsPullResponse is the body of GET /agent/assignments.
type AssignmentsPullResponse struct {
	Etag        string               `json:"etag"`
	ConfigEtag  string               `json:"configEtag"`
	Assignments []AssignmentPullItem `json:"assignments"`
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
	var resp AssignmentsPullResponse
	if err := c.doJSON(http.MethodGet, assignmentsPath, nil, true, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
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
