package node

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const nodeExtraCAEnvKey = "NODE_EXTRA_CA_CERTS"

func upsertEnvLine(path, key, value string) error {
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

	lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	content := strings.Join(lines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	return writeFileAtomic(path, []byte(content), 0o644)
}

func removeEnvLine(path, key string) error {
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
	return writeFileAtomic(path, []byte(content), 0o644)
}

func envLineMatchesKey(line, key string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "export ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
	}
	entryKey, _, ok := strings.Cut(trimmed, "=")
	return ok && strings.TrimSpace(entryKey) == key
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create env directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".env-*")
	if err != nil {
		return fmt.Errorf("create temp env file: %w", err)
	}
	tmpPath := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("write temp env file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp env file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp env file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("commit env file: %w", err)
	}

	return nil
}
