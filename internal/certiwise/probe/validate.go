package probe

import (
	"crypto/x509"
	"errors"
	"strings"
	"time"
)

const (
	validationOK               = "ok"
	validationExpired          = "expired"
	validationHostnameMismatch = "hostname_mismatch"
	validationUntrusted        = "untrusted"
	validationHandshakeError   = "handshake_error"
)

// ValidateHandshake maps probe results to schema validationResult values.
func ValidateHandshake(result HandshakeResult, expectedServerName string, insecure bool) ValidationOutcome {
	if result.DialError != nil {
		if classified := classifyFromDial(result); classified != nil {
			return *classified
		}
	}

	if len(result.PeerCerts) == 0 {
		return ValidationOutcome{
			Result: validationHandshakeError,
			Errors: []string{"empty certificate chain"},
		}
	}

	serverName := strings.TrimSpace(expectedServerName)
	if serverName == "" {
		serverName = strings.TrimSpace(result.ServerName)
	}

	return ValidatePeerCertificates(result.PeerCerts, serverName, insecure)
}

func classifyFromDial(result HandshakeResult) *ValidationOutcome {
	if result.DialError != nil {
		message := truncateError(result.DialError.Error())
		lower := strings.ToLower(message)

		switch {
		case strings.Contains(lower, "expired"):
			return &ValidationOutcome{Result: validationExpired, Errors: []string{message}}
		case strings.Contains(lower, "hostname") || strings.Contains(lower, "name mismatch"):
			return &ValidationOutcome{Result: validationHostnameMismatch, Errors: []string{message}}
		case strings.Contains(lower, "unknown authority") || strings.Contains(lower, "untrusted"):
			return &ValidationOutcome{Result: validationUntrusted, Errors: []string{message}}
		default:
			return &ValidationOutcome{Result: validationHandshakeError, Errors: []string{message}}
		}
	}
	return nil
}

// ValidatePeerCertificates validates captured peer certificates against expected server name.
func ValidatePeerCertificates(
	certs []*x509.Certificate,
	expectedServerName string,
	insecure bool,
) ValidationOutcome {
	if len(certs) == 0 {
		return ValidationOutcome{
			Result: validationHandshakeError,
			Errors: []string{"empty certificate chain"},
		}
	}

	leaf := certs[0]
	now := time.Now()

	if now.After(leaf.NotAfter) {
		return ValidationOutcome{
			Result: validationExpired,
			Errors: []string{"certificate expired at " + leaf.NotAfter.UTC().Format(time.RFC3339)},
		}
	}
	if now.Before(leaf.NotBefore) {
		return ValidationOutcome{
			Result: validationUntrusted,
			Errors: []string{"certificate not yet valid"},
		}
	}

	if expectedServerName != "" {
		if err := leaf.VerifyHostname(expectedServerName); err != nil {
			return ValidationOutcome{
				Result: validationHostnameMismatch,
				Errors: []string{truncateError(err.Error())},
			}
		}
	}

	if insecure {
		return ValidationOutcome{
			Result:        validationOK,
			Errors:        []string{},
			VerifiedChain: append([]*x509.Certificate(nil), certs...),
		}
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		if cert != nil {
			intermediates.AddCert(cert)
		}
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}

	verifyOpts := x509.VerifyOptions{
		DNSName:       expectedServerName,
		Intermediates: intermediates,
		Roots:         roots,
	}

	chains, err := leaf.Verify(verifyOpts)
	if err != nil {
		var unknownAuth x509.UnknownAuthorityError
		var hostnameErr x509.HostnameError
		switch {
		case errors.As(err, &unknownAuth):
			return ValidationOutcome{Result: validationUntrusted, Errors: []string{truncateError(err.Error())}}
		case errors.As(err, &hostnameErr):
			return ValidationOutcome{Result: validationHostnameMismatch, Errors: []string{truncateError(err.Error())}}
		default:
			return ValidationOutcome{Result: validationUntrusted, Errors: []string{truncateError(err.Error())}}
		}
	}

	return ValidationOutcome{
		Result:        validationOK,
		Errors:        []string{},
		VerifiedChain: longestVerifiedChain(chains, certs),
	}
}

func longestVerifiedChain(
	chains [][]*x509.Certificate,
	presented []*x509.Certificate,
) []*x509.Certificate {
	best := append([]*x509.Certificate(nil), presented...)
	for _, chain := range chains {
		if len(chain) > len(best) {
			best = append([]*x509.Certificate(nil), chain...)
		}
	}
	return best
}

func truncateError(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 512 {
		return message[:512]
	}
	return message
}
