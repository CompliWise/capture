package python

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

// Installer implements python_certifi_bundle for trust anchors.
type Installer struct{}

func (i *Installer) Supports(materialType, trustStoreType string) bool {
	return materialType == "trust_anchor" && trustStoreType == "python_certifi_bundle"
}

func (i *Installer) Install(_ context.Context, opts installer.InstallOptions) (string, error) {
	bundlePath, err := resolveBundlePath(opts.TrustStorePath)
	if err != nil {
		return "", err
	}

	alias := installer.DefaultAlias(opts.AssignmentID, opts.Alias)
	markerStart := fmt.Sprintf("# compliwise-%s-start", alias)
	markerEnd := fmt.Sprintf("# compliwise-%s-end", alias)
	thumbprintMarker := fmt.Sprintf("# compliwise-thumbprint:%s", strings.TrimSpace(opts.Thumbprint))

	existing, readErr := os.ReadFile(bundlePath)
	if readErr == nil {
		content := string(existing)
		if strings.Contains(content, thumbprintMarker) {
			return "idempotent: thumbprint unchanged in " + bundlePath, nil
		}
	}

	block := strings.Join([]string{
		markerStart,
		thumbprintMarker,
		strings.TrimSpace(opts.ChainPem),
		markerEnd,
		"",
	}, "\n")

	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		return "", fmt.Errorf("create bundle directory: %w", err)
	}

	file, err := os.OpenFile(bundlePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", fmt.Errorf("open bundle file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString("\n" + block); err != nil {
		return "", fmt.Errorf("append bundle: %w", err)
	}

	return fmt.Sprintf("appended cert block to %s", bundlePath), nil
}

func (i *Installer) Remove(_ context.Context, opts installer.RemoveOptions) (string, error) {
	record := opts.Record
	bundlePath := strings.TrimSpace(record.CertPath)
	if bundlePath == "" {
		return "", fmt.Errorf("missing bundle path in install record")
	}

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "bundle already absent: " + bundlePath, nil
		}
		return "", fmt.Errorf("read bundle file: %w", err)
	}

	alias := installer.DefaultAlias(record.AssignmentID, record.Alias)
	markerStart := fmt.Sprintf("# compliwise-%s-start", alias)
	markerEnd := fmt.Sprintf("# compliwise-%s-end", alias)

	content := string(data)
	start := strings.Index(content, markerStart)
	if start < 0 {
		return "marker block not found; nothing to remove", nil
	}
	end := strings.Index(content[start:], markerEnd)
	if end < 0 {
		return "", fmt.Errorf("marker end not found in bundle")
	}
	end = start + end + len(markerEnd)

	updated := content[:start] + content[end:]
	if err := os.WriteFile(bundlePath, []byte(strings.TrimRight(updated, "\n")+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write bundle file: %w", err)
	}

	return fmt.Sprintf("removed cert block from %s", bundlePath), nil
}

func resolveBundlePath(configured string) (string, error) {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed, nil
	}

	python, err := exec.LookPath("python3")
	if err != nil {
		return "", fmt.Errorf("python3 not found on PATH")
	}

	cmd := exec.Command(python, "-m", "certifi")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve certifi bundle: %w", err)
	}

	path := strings.TrimSpace(string(output))
	if path == "" {
		return "", fmt.Errorf("certifi bundle path is empty")
	}
	return path, nil
}
