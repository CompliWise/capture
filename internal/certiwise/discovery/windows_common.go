package discovery

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const (
	defaultWindowsStoreRoot = "LocalMachine\\Root"
	defaultWindowsStoreMy   = "LocalMachine\\My"
)

// CommandExecutor runs external commands for discovery scanners.
type CommandExecutor interface {
	Run(name string, args ...string) ([]byte, error)
}

type defaultCommandExecutor struct{}

func (defaultCommandExecutor) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

type powershellCertRecord struct {
	Thumbprint string `json:"Thumbprint"`
	Subject    string `json:"Subject"`
	NotAfter   string `json:"NotAfter"`
}

func resolveWindowsExecutor(opts WindowsScanOptions) CommandExecutor {
	if opts.Executor != nil {
		return opts.Executor
	}
	return defaultCommandExecutor{}
}

func windowsStorePaths(includeMy bool) []string {
	stores := []string{defaultWindowsStoreRoot}
	if includeMy {
		stores = append(stores, defaultWindowsStoreMy)
	}
	return stores
}

func buildPowerShellListArgs(store string) []string {
	script := fmt.Sprintf(
		`Get-ChildItem Cert:\%s | Select-Object Thumbprint, Subject, NotAfter | ConvertTo-Json -Compress`,
		store,
	)
	return []string{
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	}
}

func parsePowerShellCertJSON(data []byte, store string) ([]DiscoveredItem, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var records []powershellCertRecord
	if strings.HasPrefix(trimmed, "{") {
		var single powershellCertRecord
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return nil, fmt.Errorf("parse powershell cert json object: %w", err)
		}
		records = []powershellCertRecord{single}
	} else if err := json.Unmarshal([]byte(trimmed), &records); err != nil {
		return nil, fmt.Errorf("parse powershell cert json array: %w", err)
	}

	items := make([]DiscoveredItem, 0, len(records))
	for _, record := range records {
		thumbprint := normalizeWindowsThumbprint(record.Thumbprint)
		if len(thumbprint) != 64 {
			continue
		}
		items = append(items, DiscoveredItem{
			Source:         SourceWindowsCertStore,
			Path:           fmt.Sprintf(`cert:\%s\%s`, store, strings.ToUpper(record.Thumbprint)),
			Thumbprint:     thumbprint,
			SubjectCN:      extractSubjectCN(record.Subject),
			NotAfter:       normalizeWindowsNotAfter(record.NotAfter),
			TrustStoreType: SourceWindowsCertStore,
		})
	}
	return items, nil
}

func scanWindowsCertStores(opts WindowsScanOptions, maxItems int) []DiscoveredItem {
	if !opts.Enabled || maxItems <= 0 {
		return nil
	}

	executor := resolveWindowsExecutor(opts)
	var items []DiscoveredItem

	for _, store := range windowsStorePaths(opts.IncludeMy) {
		if len(items) >= maxItems {
			break
		}

		output, err := executor.Run("powershell", buildPowerShellListArgs(store)...)
		if err != nil {
			log.Printf("certiwise: discovery: windows store %s: %v", store, err)
			continue
		}

		parsed, err := parsePowerShellCertJSON(output, store)
		if err != nil {
			log.Printf("certiwise: discovery: parse windows store %s: %v", store, err)
			continue
		}

		remaining := maxItems - len(items)
		if len(parsed) > remaining {
			parsed = parsed[:remaining]
		}
		items = append(items, parsed...)
	}

	return items
}

func normalizeWindowsThumbprint(value string) string {
	cleaned := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
	if len(cleaned) == 64 {
		return cleaned
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
}

func extractSubjectCN(subject string) string {
	subject = strings.TrimSpace(subject)
	const prefix = "CN="
	idx := strings.Index(subject, prefix)
	if idx < 0 {
		return subject
	}
	rest := subject[idx+len(prefix):]
	if comma := strings.Index(rest, ","); comma >= 0 {
		return strings.TrimSpace(rest[:comma])
	}
	return strings.TrimSpace(rest)
}

func normalizeWindowsNotAfter(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		time.RFC1123,
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}
	return value
}
