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
	defaultDiscoveryMaxItems     = 500
	defaultDiscoveryInterval     = 24 * time.Hour
	defaultDiscoveryPemPaths     = "/usr/local/share/ca-certificates"
	defaultProbeInterval         = 5 * time.Minute
	defaultProbeTimeout          = 10 * time.Second
	minProbeInterval             = 30 * time.Second
	minProbeTimeout              = time.Second
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
	DiscoveryEnabled  bool
	DiscoveryInterval time.Duration
	DiscoveryPemPaths []string
	DiscoveryMaxItems int
	DiscoveryPostDeploy bool
	ProbeEnabled      bool
	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	ProbeTargets      []string
	ProbeInsecure     bool
	ProbePostDeploy   bool
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
		DiscoveryEnabled:   discoveryEnabledFromEnv(merged),
		DiscoveryInterval:  discoveryIntervalFromEnv(merged),
		DiscoveryPemPaths:  discoveryPemPathsFromEnv(merged),
		DiscoveryMaxItems:   discoveryMaxItemsFromEnv(merged),
		DiscoveryPostDeploy: discoveryPostDeployFromEnv(merged),
		ProbeEnabled:        probeEnabledFromEnv(merged),
		ProbeInterval:       probeIntervalFromEnv(merged),
		ProbeTimeout:        probeTimeoutFromEnv(merged),
		ProbeTargets:        probeTargetsFromEnv(merged),
		ProbeInsecure:       probeInsecureFromEnv(merged),
		ProbePostDeploy:     probePostDeployFromEnv(merged),
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

func discoveryEnabledFromEnv(values map[string]string) bool {
	raw := strings.TrimSpace(values["COMPLIWISE_DISCOVERY_ENABLED"])
	if raw == "" {
		return true
	}
	return !strings.EqualFold(raw, "false")
}

func discoveryIntervalFromEnv(values map[string]string) time.Duration {
	raw := strings.TrimSpace(values["COMPLIWISE_DISCOVERY_INTERVAL"])
	if raw == "" {
		return defaultDiscoveryInterval
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < time.Minute {
		return defaultDiscoveryInterval
	}
	return parsed
}

func discoveryPemPathsFromEnv(values map[string]string) []string {
	raw := strings.TrimSpace(values["COMPLIWISE_DISCOVERY_PEM_PATHS"])
	if raw == "" {
		return []string{defaultDiscoveryPemPaths}
	}
	parts := strings.Split(raw, ",")
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			paths = append(paths, trimmed)
		}
	}
	if len(paths) == 0 {
		return []string{defaultDiscoveryPemPaths}
	}
	return paths
}

func discoveryMaxItemsFromEnv(values map[string]string) int {
	raw := strings.TrimSpace(values["COMPLIWISE_DISCOVERY_MAX_ITEMS"])
	if raw == "" {
		return defaultDiscoveryMaxItems
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return defaultDiscoveryMaxItems
	}
	if value > defaultDiscoveryMaxItems {
		return defaultDiscoveryMaxItems
	}
	return value
}

func discoveryPostDeployFromEnv(values map[string]string) bool {
	raw := strings.TrimSpace(values["COMPLIWISE_DISCOVERY_POST_DEPLOY"])
	if raw == "" {
		return true
	}
	return !strings.EqualFold(raw, "false")
}

func probeEnabledFromEnv(values map[string]string) bool {
	raw := strings.TrimSpace(values["COMPLIWISE_TLS_PROBE_ENABLED"])
	if raw == "" {
		return true
	}
	return !strings.EqualFold(raw, "false")
}

func probeIntervalFromEnv(values map[string]string) time.Duration {
	raw := strings.TrimSpace(values["COMPLIWISE_TLS_PROBE_INTERVAL"])
	if raw == "" {
		return defaultProbeInterval
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < minProbeInterval {
		return defaultProbeInterval
	}
	return parsed
}

func probeTimeoutFromEnv(values map[string]string) time.Duration {
	raw := strings.TrimSpace(values["COMPLIWISE_TLS_PROBE_TIMEOUT"])
	if raw == "" {
		return defaultProbeTimeout
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < minProbeTimeout {
		return defaultProbeTimeout
	}
	return parsed
}

func probeTargetsFromEnv(values map[string]string) []string {
	raw := strings.TrimSpace(values["COMPLIWISE_TLS_PROBE_TARGETS"])
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	targets := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			targets = append(targets, trimmed)
		}
	}
	return targets
}

func probePostDeployFromEnv(values map[string]string) bool {
	raw := strings.TrimSpace(values["COMPLIWISE_TLS_PROBE_POST_DEPLOY"])
	if raw == "" {
		return true
	}
	return !strings.EqualFold(raw, "false")
}

func probeInsecureFromEnv(values map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(values["COMPLIWISE_TLS_PROBE_INSECURE"]), "true")
}
