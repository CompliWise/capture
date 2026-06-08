package certiwise

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ClientConfig holds enterprise connectivity options for CompliWise API calls.
type ClientConfig struct {
	BaseURL          string
	AgentToken       string
	ProxyURL         string
	MtlsCertPath     string
	MtlsKeyPath      string
	MtlsCAPath       string
	APICABundlePath  string
	APIPinSHA256     string
	InsecureSkipVerify bool
}

// Client performs authenticated HTTP requests to the CompliWise API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// NewClient builds an HTTP client honoring proxy, custom CA, optional mTLS, and pinning.
func NewClient(cfg ClientConfig) (*Client, error) {
	transport := &http.Transport{
		Proxy: proxyFromEnv(cfg.ProxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	if cfg.APICABundlePath != "" {
		pool, err := loadCertPool(cfg.APICABundlePath)
		if err != nil {
			return nil, fmt.Errorf("load API CA bundle: %w", err)
		}
		transport.TLSClientConfig.RootCAs = pool
	}

	if cfg.MtlsCertPath != "" && cfg.MtlsKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.MtlsCertPath, cfg.MtlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load mTLS key pair: %w", err)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.MtlsCAPath != "" {
		pool, err := loadCertPool(cfg.MtlsCAPath)
		if err != nil {
			return nil, fmt.Errorf("load mTLS CA bundle: %w", err)
		}
		if transport.TLSClientConfig.RootCAs == nil {
			transport.TLSClientConfig.RootCAs = pool
		} else {
			transport.TLSClientConfig.RootCAs = pool
		}
	}

	if cfg.APIPinSHA256 != "" {
		pin := strings.ToLower(strings.TrimSpace(cfg.APIPinSHA256))
		transport.TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		token:   cfg.AgentToken,
	}, nil
}

func proxyFromEnv(override string) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if override != "" {
			return url.Parse(override)
		}
		if env := os.Getenv("COMPLIWISE_PROXY_URL"); env != "" {
			return url.Parse(env)
		}
		return http.ProxyFromEnvironment(req)
	}
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

// NewClientFromEnv reads COMPLIWISE_* and HTTP(S)_PROXY environment variables.
func NewClientFromEnv() (*Client, error) {
	baseURL := os.Getenv("COMPLIWISE_API_URL")
	if baseURL == "" {
		return nil, fmt.Errorf("COMPLIWISE_API_URL is required")
	}

	return NewClient(ClientConfig{
		BaseURL:           baseURL,
		AgentToken:        os.Getenv("COMPLIWISE_AGENT_TOKEN"),
		ProxyURL:          os.Getenv("COMPLIWISE_PROXY_URL"),
		MtlsCertPath:      os.Getenv("COMPLIWISE_MTLS_CERT"),
		MtlsKeyPath:       os.Getenv("COMPLIWISE_MTLS_KEY"),
		MtlsCAPath:        os.Getenv("COMPLIWISE_MTLS_CA"),
		APICABundlePath:   os.Getenv("COMPLIWISE_API_CA_BUNDLE"),
		APIPinSHA256:      os.Getenv("COMPLIWISE_API_PIN_SHA256"),
		InsecureSkipVerify: strings.EqualFold(os.Getenv("COMPLIWISE_INSECURE_SKIP_VERIFY"), "true"),
	})
}
