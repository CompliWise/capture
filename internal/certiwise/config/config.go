package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bluewave-labs/capture/internal/certiwise/store"
)

const (
	DefaultAgentEnvPath          = "/etc/compliwise/agent.env"
	defaultHeartbeatIntervalSecs = 60
	defaultPollIntervalSecs      = 60
)

// Config holds CompliWise control-plane settings for the capture agent.
type Config struct {
	APIURL            string
	OrgID             string
	AgentID           string
	AgentToken        string
	EnrollmentCode    string
	HeartbeatInterval time.Duration
	PollInterval      time.Duration
	ProxyURL          string
	MtlsCertPath      string
	MtlsKeyPath       string
	MtlsCAPath        string
	APICABundlePath   string
	APIPinSHA256      string
	InsecureSkipVerify bool
	AgentEnvPath      string
}

// Load reads CompliWise settings from the persisted env file and process environment.
// Process environment overrides values from the file.
// Returns nil when COMPLIWISE_API_URL is unset (metrics-only mode).
func Load() (*Config, error) {
	envPath := envOrDefault("COMPLIWISE_AGENT_ENV_FILE", DefaultAgentEnvPath)
	fileValues, err := store.ReadEnvFile(envPath)
	if err != nil {
		if os.IsPermission(err) && strings.TrimSpace(os.Getenv("COMPLIWISE_API_URL")) != "" {
			// Docker -e injection or an entrypoint may provide config when a persisted
			// agent.env from an older container is not readable by this process user.
			fileValues = map[string]string{}
		} else {
			return nil, fmt.Errorf("read agent env file: %w", err)
		}
	}

	merged := mergeEnv(fileValues, os.Environ())
	apiURL := strings.TrimSpace(merged["COMPLIWISE_API_URL"])
	if apiURL == "" {
		return nil, nil
	}

	cfg := &Config{
		APIURL:             apiURL,
		OrgID:              strings.TrimSpace(merged["COMPLIWISE_ORG_ID"]),
		AgentID:            strings.TrimSpace(merged["COMPLIWISE_AGENT_ID"]),
		AgentToken:         strings.TrimSpace(merged["COMPLIWISE_AGENT_TOKEN"]),
		EnrollmentCode:     strings.TrimSpace(merged["COMPLIWISE_ENROLLMENT_CODE"]),
		HeartbeatInterval:  durationFromEnv(merged, "COMPLIWISE_HEARTBEAT_INTERVAL", defaultHeartbeatIntervalSecs),
		PollInterval:       durationFromEnv(merged, "COMPLIWISE_POLL_INTERVAL", defaultPollIntervalSecs),
		ProxyURL:           strings.TrimSpace(merged["COMPLIWISE_PROXY_URL"]),
		MtlsCertPath:       strings.TrimSpace(merged["COMPLIWISE_MTLS_CERT"]),
		MtlsKeyPath:        strings.TrimSpace(merged["COMPLIWISE_MTLS_KEY"]),
		MtlsCAPath:         strings.TrimSpace(merged["COMPLIWISE_MTLS_CA"]),
		APICABundlePath:    strings.TrimSpace(merged["COMPLIWISE_API_CA_BUNDLE"]),
		APIPinSHA256:       strings.TrimSpace(merged["COMPLIWISE_API_PIN_SHA256"]),
		InsecureSkipVerify: strings.EqualFold(merged["COMPLIWISE_INSECURE_SKIP_VERIFY"], "true"),
		AgentEnvPath:       envPath,
	}

	return cfg, nil
}

func mergeEnv(fileValues map[string]string, environ []string) map[string]string {
	merged := make(map[string]string, len(fileValues)+len(environ))
	for key, value := range fileValues {
		merged[key] = value
	}
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		merged[key] = value
	}
	return merged
}

func durationFromEnv(values map[string]string, key string, defaultSeconds int) time.Duration {
	raw := strings.TrimSpace(values[key])
	if raw == "" {
		return time.Duration(defaultSeconds) * time.Second
	}

	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 15 {
		return time.Duration(defaultSeconds) * time.Second
	}

	return time.Duration(seconds) * time.Second
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
