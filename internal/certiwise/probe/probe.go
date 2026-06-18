package probe

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/compliwise/capture/internal/certiwise"
	cwconfig "github.com/compliwise/capture/internal/certiwise/config"
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

	chain, subjectCns := selectChainFields(
		handshake.ChainSHA256,
		handshake.PeerCerts,
		outcome.VerifiedChain,
	)
	tlsVersion := handshake.TLSVersion
	cipherSuite := handshake.CipherSuite

	if len(chain) == 0 {
		chain = []string{handshakeErrorThumbprint}
		subjectCns = nil
		tlsVersion = "TLS1.0"
		cipherSuite = "TLS_FALLBACK_SCSV"
	}

	return ProbeResult{
		ServerName:              serverName,
		PeerAddress:             peerAddress,
		TLSVersion:              tlsVersion,
		CipherSuite:             cipherSuite,
		PresentedChainSha256:    chain,
		PresentedChainSubjectCN: subjectCns,
		ValidationResult:        outcome.Result,
		ValidationErrors:        outcome.Errors,
		DurationMs:              handshake.DurationMs,
	}
}

func selectChainFields(
	presentedThumbprints []string,
	presentedCerts []*x509.Certificate,
	verified []*x509.Certificate,
) ([]string, []string) {
	verifiedThumbprints := chainThumbprints(verified)
	verifiedSubjectCns := chainSubjectCNs(verified)
	if len(verifiedThumbprints) > len(presentedThumbprints) {
		return verifiedThumbprints, verifiedSubjectCns
	}
	if len(presentedThumbprints) > 0 {
		return presentedThumbprints, chainSubjectCNs(presentedCerts)
	}
	return verifiedThumbprints, verifiedSubjectCns
}
