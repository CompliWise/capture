package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadReturnsNilWithoutAPIURL(t *testing.T) {
	t.Setenv("COMPLIWISE_API_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config when COMPLIWISE_API_URL is unset")
	}
}

func TestLoadIgnoresUnreadableEnvFileWhenProcessEnvHasAPIURL(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte("COMPLIWISE_API_URL=http://file.example\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)
	t.Setenv("COMPLIWISE_API_URL", "http://process.example")
	t.Setenv("COMPLIWISE_AGENT_TOKEN", "cw_agent_from_env")

	if err := os.Chmod(envPath, 0o000); err != nil {
		t.Fatalf("chmod env file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(envPath, 0o600)
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIURL != "http://process.example" {
		t.Fatalf("expected process env API URL, got %q", cfg.APIURL)
	}
	if cfg.AgentToken != "cw_agent_from_env" {
		t.Fatalf("expected token from process env, got %q", cfg.AgentToken)
	}
}

func TestLoadMergesEnvFileAndProcessEnv(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte(`COMPLIWISE_API_URL=http://file.example
COMPLIWISE_AGENT_TOKEN=cw_agent_from_file
COMPLIWISE_HEARTBEAT_INTERVAL=120
`), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)
	t.Setenv("COMPLIWISE_API_URL", "http://process.example")
	t.Setenv("COMPLIWISE_ORG_ID", "org-123")
	t.Setenv("COMPLIWISE_AGENT_ID", "agent-123")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIURL != "http://process.example" {
		t.Fatalf("expected process env to override file, got %q", cfg.APIURL)
	}
	if cfg.AgentToken != "cw_agent_from_file" {
		t.Fatalf("expected token from file, got %q", cfg.AgentToken)
	}
	if cfg.HeartbeatInterval != 120*time.Second {
		t.Fatalf("expected 120s heartbeat interval, got %s", cfg.HeartbeatInterval)
	}
}

func TestLoadDiscoveryConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte("COMPLIWISE_API_URL=http://file.example\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DiscoveryEnabled {
		t.Fatal("expected discovery enabled by default")
	}
	if cfg.DiscoveryInterval != 24*time.Hour {
		t.Fatalf("expected 24h discovery interval, got %s", cfg.DiscoveryInterval)
	}
	if cfg.DiscoveryMaxItems != 500 {
		t.Fatalf("expected max items 500, got %d", cfg.DiscoveryMaxItems)
	}
	if !cfg.DiscoveryPostDeploy {
		t.Fatal("expected post-deploy discovery enabled by default")
	}
	if len(cfg.DiscoveryPemPaths) != 1 || cfg.DiscoveryPemPaths[0] != "/usr/local/share/ca-certificates" {
		t.Fatalf("unexpected pem paths: %#v", cfg.DiscoveryPemPaths)
	}
}

func TestLoadDiscoveryTLSConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte("COMPLIWISE_API_URL=http://file.example\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DiscoveryTLSEnabled {
		t.Fatal("expected TLS listener discovery enabled by default")
	}
	if cfg.DiscoveryTLSPorts != nil {
		t.Fatalf("expected nil static ports for default list fallback, got %#v", cfg.DiscoveryTLSPorts)
	}
	if cfg.DiscoveryTLSPortsExplicit {
		t.Fatal("expected explicit ports flag false when env unset")
	}
	if cfg.DiscoveryTLSTimeout != 3*time.Second {
		t.Fatalf("expected 3s TLS timeout, got %s", cfg.DiscoveryTLSTimeout)
	}
	if !cfg.DiscoveryTLSInsecure {
		t.Fatal("expected TLS insecure enabled by default")
	}
	if len(cfg.DiscoveryTLSHosts) != 2 {
		t.Fatalf("expected 2 default hosts, got %#v", cfg.DiscoveryTLSHosts)
	}
}

func TestLoadDiscoveryTLSConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte(`COMPLIWISE_API_URL=http://file.example
COMPLIWISE_DISCOVERY_TLS_ENABLED=false
COMPLIWISE_DISCOVERY_TLS_PORTS=9443,10443
COMPLIWISE_DISCOVERY_TLS_PORT_RANGE=8000-8010
COMPLIWISE_DISCOVERY_TLS_HOSTS=127.0.0.1
COMPLIWISE_DISCOVERY_TLS_TIMEOUT=2s
COMPLIWISE_DISCOVERY_TLS_INSECURE=false
`), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DiscoveryTLSEnabled {
		t.Fatal("expected TLS listener discovery disabled")
	}
	if !cfg.DiscoveryTLSPortsExplicit {
		t.Fatal("expected explicit ports flag true when env set")
	}
	if len(cfg.DiscoveryTLSPorts) != 2 || cfg.DiscoveryTLSPorts[0] != 9443 {
		t.Fatalf("unexpected TLS ports: %#v", cfg.DiscoveryTLSPorts)
	}
	if cfg.DiscoveryTLSPortRange != "8000-8010" {
		t.Fatalf("unexpected port range: %q", cfg.DiscoveryTLSPortRange)
	}
	if cfg.DiscoveryTLSTimeout != 2*time.Second {
		t.Fatalf("expected 2s TLS timeout, got %s", cfg.DiscoveryTLSTimeout)
	}
	if cfg.DiscoveryTLSInsecure {
		t.Fatal("expected TLS insecure disabled")
	}
}

func TestLoadDiscoveryJavaWindowsConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte("COMPLIWISE_API_URL=http://file.example\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DiscoveryJavaEnabled {
		t.Fatal("expected java discovery enabled by default")
	}
	if cfg.DiscoveryJavaMaxJvms != 5 {
		t.Fatalf("expected default max jvms 5, got %d", cfg.DiscoveryJavaMaxJvms)
	}
	if !cfg.DiscoveryWindowsEnabled {
		t.Fatal("expected windows discovery enabled by default")
	}
	if cfg.DiscoveryWindowsIncludeMy {
		t.Fatal("expected windows My store excluded by default")
	}
}

func TestLoadProbeConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte("COMPLIWISE_API_URL=http://file.example\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ProbeEnabled {
		t.Fatal("expected probe enabled by default")
	}
	if cfg.ProbeInterval != 5*time.Minute {
		t.Fatalf("expected 5m probe interval, got %s", cfg.ProbeInterval)
	}
	if cfg.ProbeTimeout != 10*time.Second {
		t.Fatalf("expected 10s probe timeout, got %s", cfg.ProbeTimeout)
	}
	if cfg.ProbeInsecure {
		t.Fatal("expected probe insecure disabled by default")
	}
	if !cfg.ProbePostDeploy {
		t.Fatal("expected post-deploy probe enabled by default")
	}
}

func TestLoadProbeConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte(`COMPLIWISE_API_URL=http://file.example
COMPLIWISE_TLS_PROBE_ENABLED=false
COMPLIWISE_TLS_PROBE_INTERVAL=2m
COMPLIWISE_TLS_PROBE_TIMEOUT=5s
COMPLIWISE_TLS_PROBE_TARGETS=https://probe.example:443/,https://other.example:8443/
COMPLIWISE_TLS_PROBE_INSECURE=true
COMPLIWISE_TLS_PROBE_POST_DEPLOY=false
`), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ProbeEnabled {
		t.Fatal("expected probe disabled")
	}
	if cfg.ProbeInterval != 2*time.Minute {
		t.Fatalf("expected 2m probe interval, got %s", cfg.ProbeInterval)
	}
	if cfg.ProbeTimeout != 5*time.Second {
		t.Fatalf("expected 5s probe timeout, got %s", cfg.ProbeTimeout)
	}
	if len(cfg.ProbeTargets) != 2 {
		t.Fatalf("expected 2 probe targets, got %#v", cfg.ProbeTargets)
	}
	if !cfg.ProbeInsecure {
		t.Fatal("expected probe insecure enabled")
	}
	if cfg.ProbePostDeploy {
		t.Fatal("expected post-deploy probe disabled")
	}
}

func TestLoadSyntheticConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte("COMPLIWISE_API_URL=http://file.example\n"), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.SyntheticEnabled {
		t.Fatal("expected synthetic enabled by default")
	}
	if cfg.SyntheticSyncInterval != 5*time.Minute {
		t.Fatalf("expected 5m sync interval, got %s", cfg.SyntheticSyncInterval)
	}
	if cfg.SyntheticMaxWorkers != 10 {
		t.Fatalf("expected 10 max workers, got %d", cfg.SyntheticMaxWorkers)
	}
	if cfg.SyntheticUserAgent != defaultSyntheticUserAgent {
		t.Fatalf("unexpected user agent: %q", cfg.SyntheticUserAgent)
	}
}

func TestLoadSyntheticConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(envPath, []byte(`COMPLIWISE_API_URL=http://file.example
COMPLIWISE_SYNTHETIC_ENABLED=false
COMPLIWISE_SYNTHETIC_SYNC_INTERVAL=2m
COMPLIWISE_SYNTHETIC_MAX_WORKERS=25
COMPLIWISE_SYNTHETIC_USER_AGENT=Custom-Agent/{version}
`), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	t.Setenv("COMPLIWISE_AGENT_ENV_FILE", envPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SyntheticEnabled {
		t.Fatal("expected synthetic disabled")
	}
	if cfg.SyntheticSyncInterval != 2*time.Minute {
		t.Fatalf("expected 2m sync interval, got %s", cfg.SyntheticSyncInterval)
	}
	if cfg.SyntheticMaxWorkers != 25 {
		t.Fatalf("expected 25 max workers, got %d", cfg.SyntheticMaxWorkers)
	}
	if cfg.SyntheticUserAgent != "Custom-Agent/{version}" {
		t.Fatalf("unexpected user agent: %q", cfg.SyntheticUserAgent)
	}
}
