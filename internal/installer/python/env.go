package python

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const requestsCAEnvKey = "REQUESTS_CA_BUNDLE"

func upsertEnvExport(path, key, value string) error {
	lines := []string{}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				lines = append(lines, line)
				continue
			}
			if envLineMatchesKey(trimmed, key) {
				continue
			}
			lines = append(lines, line)
		}
	}

	lines = append(lines, fmt.Sprintf("export %s=%s", key, value))
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create env directory: %w", err)
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func removeEnvExport(path, key string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if envLineMatchesKey(trimmed, key) {
			continue
		}
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	if content == "" {
		return os.Remove(path)
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func envLineMatchesKey(line, key string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "export ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
	}
	entryKey, _, ok := strings.Cut(trimmed, "=")
	return ok && strings.TrimSpace(entryKey) == key
}
