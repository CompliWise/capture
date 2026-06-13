package probe

import (
	"context"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

// ResolveTargetsFromConfig resolves probe targets from config and assignments pull.
func ResolveTargetsFromConfig(
	cfg *cwconfig.Config,
	pull *certiwise.AssignmentsPullResponse,
) ([]ProbeTarget, error) {
	if cfg == nil {
		return nil, nil
	}
	assignments := []certiwise.AssignmentPullItem{}
	if pull != nil {
		assignments = pull.Assignments
	}
	return ResolveTargets(cfg.ProbeTargets, assignments)
}

// Probe runs a full TLS probe for one target.
func Probe(ctx context.Context, target ProbeTarget, cfg *cwconfig.Config) ProbeResult {
	timeout := 10 * time.Second
	if cfg != nil && cfg.ProbeTimeout > 0 {
		timeout = cfg.ProbeTimeout
	}
	insecure := cfg != nil && cfg.ProbeInsecure

	opts := HandshakeOptions{
		Timeout:            timeout,
		InsecureSkipVerify: insecure,
	}

	handshake := ProbeHandshake(ctx, target, opts)
	outcome := ValidateHandshake(handshake, target.ServerName, insecure)

	serverName := handshake.ServerName
	if serverName == "" {
		serverName = target.ServerName
	}
	if serverName == "" {
		serverName = target.Host
	}

	peerAddress := handshake.PeerAddress
	if peerAddress == "" {
		peerAddress = PeerAddressForTarget(target)
	}

	chain := handshake.ChainSHA256
	tlsVersion := handshake.TLSVersion
	cipherSuite := handshake.CipherSuite

	if len(chain) == 0 {
		chain = []string{handshakeErrorThumbprint}
		tlsVersion = "TLS1.0"
		cipherSuite = "TLS_FALLBACK_SCSV"
	}

	return ProbeResult{
		ServerName:           serverName,
		PeerAddress:          peerAddress,
		TLSVersion:           tlsVersion,
		CipherSuite:          cipherSuite,
		PresentedChainSha256: chain,
		ValidationResult:     outcome.Result,
		ValidationErrors:     outcome.Errors,
		DurationMs:           handshake.DurationMs,
	}
}
