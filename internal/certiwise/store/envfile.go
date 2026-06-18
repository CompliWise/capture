package store

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadEnvFile loads KEY=VALUE pairs from a dotenv-style file.
// Missing files return an empty map.
func ReadEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return values, nil
}

// WriteEnvFile persists agent settings after enrollment.
func WriteEnvFile(path string, values map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create agent env directory: %w", err)
	}

	var builder strings.Builder
	keys := []string{
		"COMPLIWISE_API_URL",
		"COMPLIWISE_ORG_ID",
		"COMPLIWISE_AGENT_ID",
		"COMPLIWISE_AGENT_TOKEN",
		"COMPLIWISE_POLL_INTERVAL",
		"COMPLIWISE_HEARTBEAT_INTERVAL",
		"COMPLIWISE_TELEMETRY_BATCH_SIZE",
		"COMPLIWISE_TELEMETRY_FLUSH_SECONDS",
	}
	for _, key := range keys {
		value, ok := values[key]
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(value)
		builder.WriteString("\n")
	}

	content := builder.String()
	if content == "" {
		return fmt.Errorf("refusing to write empty agent env file")
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write agent env file: %w", err)
	}

	return nil
}
