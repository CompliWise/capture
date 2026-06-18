package certiwise

// ConnectivityTestStep is one diagnostic step in a connectivity test result.
type ConnectivityTestStep struct {
	Step       string `json:"step"`
	Passed     bool   `json:"passed"`
	Message    string `json:"message"`
	DurationMs int    `json:"durationMs"`
}
