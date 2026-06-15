package connectivity

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise"
	cwconfig "github.com/bluewave-labs/capture/internal/certiwise/config"
)

// RunProbe executes connectivity steps against the configured API base URL only.
func RunProbe(
	ctx context.Context,
	cfg *cwconfig.Config,
	client *certiwise.Client,
) []certiwise.ConnectivityTestStep {
	if cfg == nil {
		return failedAllSteps("connectivity config is missing")
	}

	opts := probeOptionsFromConfig(cfg)
	parsed, err := parseAPIBaseURL(opts.BaseURL)
	if err != nil {
		return failedAllSteps(err.Error())
	}

	steps := make([]certiwise.ConnectivityTestStep, 0, 4)

	dnsStep := runDNSResolve(ctx, parsed.Hostname())
	steps = append(steps, dnsStep)
	if !dnsStep.Passed {
		steps = append(steps, skippedTCPConnect(), skippedTLSHandshake(), skippedAPIAuth())
		return steps
	}

	tcpStep := runTCPConnect(ctx, parsed, opts)
	steps = append(steps, tcpStep)
	if !tcpStep.Passed {
		steps = append(steps, skippedTLSHandshake(), skippedAPIAuth())
		return steps
	}

	tlsStep := runTLSHandshake(ctx, parsed, opts)
	steps = append(steps, tlsStep)
	if !tlsStep.Passed {
		steps = append(steps, skippedAPIAuth())
		return steps
	}

	steps = append(steps, runAPIAuth(ctx, client))
	return steps
}

type probeOptions struct {
	BaseURL            string
	ProxyURL           string
	MtlsCertPath       string
	MtlsKeyPath        string
	MtlsCAPath         string
	APICABundlePath    string
	APIPinSHA256       string
	InsecureSkipVerify bool
}

func probeOptionsFromConfig(cfg *cwconfig.Config) probeOptions {
	return probeOptions{
		BaseURL:            cfg.APIURL,
		ProxyURL:           cfg.ProxyURL,
		MtlsCertPath:       cfg.MtlsCertPath,
		MtlsKeyPath:        cfg.MtlsKeyPath,
		MtlsCAPath:         cfg.MtlsCAPath,
		APICABundlePath:    cfg.APICABundlePath,
		APIPinSHA256:       cfg.APIPinSHA256,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
}

func parseAPIBaseURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("API base URL is not configured")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid API base URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("API base URL must use http or https")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return nil, fmt.Errorf("API base URL host is required")
	}
	return parsed, nil
}

func runDNSResolve(ctx context.Context, hostname string) certiwise.ConnectivityTestStep {
	started := time.Now()
	_, err := net.DefaultResolver.LookupHost(ctx, hostname)
	durationMs := int(time.Since(started).Milliseconds())

	if err != nil {
		return certiwise.ConnectivityTestStep{
			Step:       StepDNSResolve,
			Passed:     false,
			Message:    truncateMessage(fmt.Sprintf("DNS lookup failed for %s: %v", hostname, err)),
			DurationMs: durationMs,
		}
	}

	return certiwise.ConnectivityTestStep{
		Step:       StepDNSResolve,
		Passed:     true,
		Message:    truncateMessage(fmt.Sprintf("Resolved %s", hostname)),
		DurationMs: durationMs,
	}
}

func runTCPConnect(ctx context.Context, parsed *url.URL, opts probeOptions) certiwise.ConnectivityTestStep {
	started := time.Now()
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	address := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	durationMs := int(time.Since(started).Milliseconds())

	if err != nil {
		return certiwise.ConnectivityTestStep{
			Step:       StepTCPConnect,
			Passed:     false,
			Message:    truncateMessage(fmt.Sprintf("TCP connect to %s failed: %v", address, err)),
			DurationMs: durationMs,
		}
	}
	_ = conn.Close()

	message := fmt.Sprintf("Connected to %s", address)
	if proxyConfigured(opts) {
		message += "; proxy environment configured"
	}

	return certiwise.ConnectivityTestStep{
		Step:       StepTCPConnect,
		Passed:     true,
		Message:    truncateMessage(message),
		DurationMs: durationMs,
	}
}

func runTLSHandshake(ctx context.Context, parsed *url.URL, opts probeOptions) certiwise.ConnectivityTestStep {
	started := time.Now()

	if opts.APICABundlePath != "" {
		if _, err := os.ReadFile(opts.APICABundlePath); err != nil {
			durationMs := int(time.Since(started).Milliseconds())
			return certiwise.ConnectivityTestStep{
				Step:       StepTLSHandshake,
				Passed:     false,
				Message:    truncateMessage(fmt.Sprintf("API CA bundle not readable: %v", err)),
				DurationMs: durationMs,
			}
		}
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if parsed.Scheme != "https" {
		durationMs := int(time.Since(started).Milliseconds())
		return certiwise.ConnectivityTestStep{
			Step:       StepTLSHandshake,
			Passed:     true,
			Message:    truncateMessage("TLS not required for http API base URL"),
			DurationMs: durationMs,
		}
	}

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	if opts.APICABundlePath != "" {
		pool, err := loadCertPool(opts.APICABundlePath)
		if err != nil {
			durationMs := int(time.Since(started).Milliseconds())
			return certiwise.ConnectivityTestStep{
				Step:       StepTLSHandshake,
				Passed:     false,
				Message:    truncateMessage(fmt.Sprintf("load API CA bundle: %v", err)),
				DurationMs: durationMs,
			}
		}
		tlsConfig.RootCAs = pool
	}

	mtlsConfigured := opts.MtlsCertPath != "" && opts.MtlsKeyPath != ""
	if mtlsConfigured {
		cert, err := tls.LoadX509KeyPair(opts.MtlsCertPath, opts.MtlsKeyPath)
		if err != nil {
			durationMs := int(time.Since(started).Milliseconds())
			return certiwise.ConnectivityTestStep{
				Step:       StepTLSHandshake,
				Passed:     false,
				Message:    truncateMessage(fmt.Sprintf("load mTLS key pair: %v", err)),
				DurationMs: durationMs,
			}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if opts.MtlsCAPath != "" {
		pool, err := loadCertPool(opts.MtlsCAPath)
		if err != nil {
			durationMs := int(time.Since(started).Milliseconds())
			return certiwise.ConnectivityTestStep{
				Step:       StepTLSHandshake,
				Passed:     false,
				Message:    truncateMessage(fmt.Sprintf("load mTLS CA bundle: %v", err)),
				DurationMs: durationMs,
			}
		}
		tlsConfig.RootCAs = pool
	}

	if opts.APIPinSHA256 != "" {
		pin := strings.ToLower(strings.TrimSpace(opts.APIPinSHA256))
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificate for pin verification")
			}
			sum := sha256.Sum256(rawCerts[0])
			if hex.EncodeToString(sum[:]) != pin {
				return fmt.Errorf("API certificate pin mismatch")
			}
			return nil
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	address := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	durationMs := int(time.Since(started).Milliseconds())

	if err != nil {
		return certiwise.ConnectivityTestStep{
			Step:       StepTLSHandshake,
			Passed:     false,
			Message:    truncateMessage(fmt.Sprintf("TLS handshake failed: %v", err)),
			DurationMs: durationMs,
		}
	}
	_ = conn.Close()

	message := "TLS handshake succeeded"
	if mtlsConfigured {
		message += "; mutual TLS handshake succeeded"
	}

	return certiwise.ConnectivityTestStep{
		Step:       StepTLSHandshake,
		Passed:     true,
		Message:    truncateMessage(message),
		DurationMs: durationMs,
	}
}

func runAPIAuth(ctx context.Context, client *certiwise.Client) certiwise.ConnectivityTestStep {
	started := time.Now()
	if ctx.Err() != nil {
		return certiwise.ConnectivityTestStep{
			Step:       StepAPIAuth,
			Passed:     false,
			Message:    truncateMessage(ctx.Err().Error()),
			DurationMs: int(time.Since(started).Milliseconds()),
		}
	}

	_, err := client.PullAssignments()
	durationMs := int(time.Since(started).Milliseconds())

	if err != nil {
		return certiwise.ConnectivityTestStep{
			Step:       StepAPIAuth,
			Passed:     false,
			Message:    truncateMessage(fmt.Sprintf("API auth check failed: %v", err)),
			DurationMs: durationMs,
		}
	}

	return certiwise.ConnectivityTestStep{
		Step:       StepAPIAuth,
		Passed:     true,
		Message:    truncateMessage("API returned 200"),
		DurationMs: durationMs,
	}
}

func proxyConfigured(opts probeOptions) bool {
	if strings.TrimSpace(opts.ProxyURL) != "" {
		return true
	}
	return strings.TrimSpace(os.Getenv("HTTPS_PROXY")) != "" ||
		strings.TrimSpace(os.Getenv("HTTP_PROXY")) != "" ||
		strings.TrimSpace(os.Getenv("COMPLIWISE_PROXY_URL")) != ""
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

func truncateMessage(message string) string {
	message = strings.TrimSpace(message)
	if len(message) <= maxStepMessageLen {
		return message
	}
	return message[:maxStepMessageLen]
}

func failedAllSteps(reason string) []certiwise.ConnectivityTestStep {
	reason = truncateMessage(reason)
	return []certiwise.ConnectivityTestStep{
		{Step: StepDNSResolve, Passed: false, Message: reason},
		{Step: StepTCPConnect, Passed: false, Message: "skipped"},
		{Step: StepTLSHandshake, Passed: false, Message: "skipped"},
		{Step: StepAPIAuth, Passed: false, Message: "skipped"},
	}
}

func skippedTCPConnect() certiwise.ConnectivityTestStep {
	return certiwise.ConnectivityTestStep{Step: StepTCPConnect, Passed: false, Message: "skipped"}
}

func skippedTLSHandshake() certiwise.ConnectivityTestStep {
	return certiwise.ConnectivityTestStep{Step: StepTLSHandshake, Passed: false, Message: "skipped"}
}

func skippedAPIAuth() certiwise.ConnectivityTestStep {
	return certiwise.ConnectivityTestStep{Step: StepAPIAuth, Passed: false, Message: "skipped"}
}
