package connectivity

const (
	StepDNSResolve   = "dns_resolve"
	StepTCPConnect   = "tcp_connect"
	StepTLSHandshake = "tls_handshake"
	StepAPIAuth      = "api_auth"
	maxStepMessageLen = 512
)
