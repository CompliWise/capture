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
