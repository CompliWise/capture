package synthetic

// Status values for synthetic check results.
const (
	StatusUp       = "up"
	StatusDown     = "down"
	StatusDegraded = "degraded"
)

// Monitor is one synthetic monitor assignment from the control plane.
type Monitor struct {
	ID              string
	URL             string
	IntervalSeconds int
	TimeoutMs       int
	Assertions      Assertions
}

// Assertions holds optional HTTPS/TLS check rules.
type Assertions struct {
	MinTlsVersion      string
	MaxDaysUntilExpiry int
	ExpectedSan        []string
	MaxResponseTimeMs  int
	ExpectHttpStatus   int
}

// CheckResult is the outcome of one synthetic HTTPS probe.
type CheckResult struct {
	Status            string
	ResponseTimeMs    int
	HTTPStatusCode    int
	CertExpiresAt     string
	CertDaysRemaining int
	ErrorMessage      string
}
