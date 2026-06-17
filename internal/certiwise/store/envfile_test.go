package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndReadEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.env")

	err := WriteEnvFile(path, map[string]string{
		"COMPLIWISE_API_URL":                  "http://localhost:4000",
		"COMPLIWISE_ORG_ID":                   "org-1",
		"COMPLIWISE_AGENT_ID":                 "agent-1",
		"COMPLIWISE_AGENT_TOKEN":              "cw_agent_test",
		"COMPLIWISE_TELEMETRY_BATCH_SIZE":     "25",
		"COMPLIWISE_TELEMETRY_FLUSH_SECONDS":  "20",
	})
	if err != nil {
		t.Fatalf("WriteEnvFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	values, err := ReadEnvFile(path)
	if err != nil {
		t.Fatalf("ReadEnvFile: %v", err)
	}
	if values["COMPLIWISE_AGENT_TOKEN"] != "cw_agent_test" {
		t.Fatalf("unexpected token: %q", values["COMPLIWISE_AGENT_TOKEN"])
	}
	if values["COMPLIWISE_TELEMETRY_BATCH_SIZE"] != "25" {
		t.Fatalf("unexpected telemetry batch: %q", values["COMPLIWISE_TELEMETRY_BATCH_SIZE"])
	}
}
