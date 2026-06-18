package certiwise

import (
	"net/http"
)

const syntheticMonitorsPath = "/api/v1/agent/synthetic-monitors"

// SyntheticAssertions mirrors monitor assertion rules from the API.
type SyntheticAssertions struct {
	MinTLSVersion      string   `json:"minTlsVersion"`
	MaxDaysUntilExpiry int      `json:"maxDaysUntilExpiry"`
	ExpectedSan        []string `json:"expectedSan,omitempty"`
	MaxResponseTimeMs  int      `json:"maxResponseTimeMs,omitempty"`
	ExpectHTTPStatus   int      `json:"expectHttpStatus,omitempty"`
}

// SyntheticMonitorPullItem is one monitor returned by GET /agent/synthetic-monitors.
type SyntheticMonitorPullItem struct {
	ID              string              `json:"id"`
	URL             string              `json:"url"`
	IntervalSeconds int                 `json:"intervalSeconds"`
	TimeoutMs       int                 `json:"timeoutMs"`
	Assertions      SyntheticAssertions `json:"assertions"`
}

// SyntheticMonitorsResponse is the body of GET /agent/synthetic-monitors.
type SyntheticMonitorsResponse struct {
	Monitors []SyntheticMonitorPullItem `json:"monitors"`
}

// PullSyntheticMonitors fetches enabled synthetic monitors assigned to this agent.
func (c *Client) PullSyntheticMonitors() (*SyntheticMonitorsResponse, error) {
	var resp SyntheticMonitorsResponse
	if err := c.doJSON(http.MethodGet, syntheticMonitorsPath, nil, true, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
