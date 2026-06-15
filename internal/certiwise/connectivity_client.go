package certiwise

import "net/http"

const connectivityTestPath = "/api/v1/agent/connectivity-test"

type submitConnectivityTestBody struct {
	Steps []ConnectivityTestStep `json:"steps"`
}

// SubmitConnectivityTest posts probe step results to the control plane.
func (c *Client) SubmitConnectivityTest(steps []ConnectivityTestStep) error {
	body := submitConnectivityTestBody{Steps: steps}
	return c.doJSON(http.MethodPost, connectivityTestPath, body, true, nil)
}
