package probe

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/bluewave-labs/capture/internal/certiwise"
)

// ResolveTargets merges env probe URLs and assignment verify endpoints.
// Env targets take precedence; duplicates are removed by serverName|peerAddress key.
func ResolveTargets(
	envTargets []string,
	assignments []certiwise.AssignmentPullItem,
) ([]ProbeTarget, error) {
	seen := make(map[string]struct{})
	targets := make([]ProbeTarget, 0)

	for _, raw := range envTargets {
		target, err := ParseProbeURL(raw)
		if err != nil {
			return nil, fmt.Errorf("parse env target %q: %w", raw, err)
		}
		key := targetKey(target)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}

	for _, assignment := range assignments {
		endpoint := strings.TrimSpace(assignment.Config.VerifyEndpoint)
		if endpoint == "" {
			continue
		}

		target, err := ParseProbeURL(endpoint)
		if err != nil {
			continue
		}

		serverName := strings.TrimSpace(assignment.Config.VerifyServerName)
		if serverName != "" {
			target.ServerName = serverName
		}

		target.ApplicationID = assignment.ApplicationID
		target.CertificateID = assignment.CertificateID
		target.DeploymentID = assignment.DeploymentID

		key := targetKey(target)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}

	return targets, nil
}

// ParseProbeURL parses an https URL into a ProbeTarget.
func ParseProbeURL(raw string) (ProbeTarget, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ProbeTarget{}, fmt.Errorf("empty probe URL")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ProbeTarget{}, err
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" {
		return ProbeTarget{}, fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return ProbeTarget{}, fmt.Errorf("missing host")
	}

	port := 443
	if portRaw := parsed.Port(); portRaw != "" {
		value, err := strconv.Atoi(portRaw)
		if err != nil || value < 1 || value > 65535 {
			return ProbeTarget{}, fmt.Errorf("invalid port %q", portRaw)
		}
		port = value
	}

	return ProbeTarget{
		URL:        trimmed,
		Host:       host,
		Port:       port,
		ServerName: host,
	}, nil
}

// TargetFromAssignment builds a probe target from one assignment verify endpoint.
func TargetFromAssignment(assignment certiwise.AssignmentPullItem) (ProbeTarget, bool) {
	endpoint := strings.TrimSpace(assignment.Config.VerifyEndpoint)
	if endpoint == "" {
		return ProbeTarget{}, false
	}

	target, err := ParseProbeURL(endpoint)
	if err != nil {
		return ProbeTarget{}, false
	}

	if serverName := strings.TrimSpace(assignment.Config.VerifyServerName); serverName != "" {
		target.ServerName = serverName
	}

	target.ApplicationID = assignment.ApplicationID
	target.CertificateID = assignment.CertificateID
	target.DeploymentID = assignment.DeploymentID
	return target, true
}

// PeerAddressForTarget returns the dial address host:port string.
func PeerAddressForTarget(target ProbeTarget) string {
	port := target.Port
	if port <= 0 {
		port = 443
	}
	return net.JoinHostPort(target.Host, strconv.Itoa(port))
}
