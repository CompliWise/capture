package discovery

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	defaultJavaMaxJvms     = 5
	defaultJavaStorePass   = "changeit"
	javaCacertsTrustType   = "java_cacerts"
)

var (
	keytoolAliasPattern    = regexp.MustCompile(`(?m)^Alias name:\s*(.+)$`)
	keytoolSHA256Pattern   = regexp.MustCompile(`(?m)^\s*SHA256:\s*([0-9A-Fa-f:\s]+)$`)
	keytoolUntilPattern    = regexp.MustCompile(`(?m)Valid from:.* until:\s*(.+)$`)
)

// ScanJavaCacerts enumerates trusted certificates from JVM cacerts keystores.
func ScanJavaCacerts(opts JavaScanOptions, maxItems int) ([]DiscoveredItem, ScanMetadata) {
	meta := ScanMetadata{}
	if !opts.Enabled || maxItems <= 0 {
		return nil, meta
	}

	maxJvms := opts.MaxJvms
	if maxJvms <= 0 {
		maxJvms = defaultJavaMaxJvms
	}

	homes := resolveJavaHomes()
	meta = ScanMetadata{JavaCacertsJvmTotal: len(homes)}
	if len(homes) == 0 {
		return nil, meta
	}

	homes, meta = capJavaHomes(homes, maxJvms)

	password := resolveJavaStorePassword(opts.StorePassword)
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		log.Printf("certiwise: discovery: keytool not found on PATH")
		return nil, meta
	}

	var items []DiscoveredItem
	for _, home := range homes {
		if len(items) >= maxItems {
			break
		}

		cacerts := resolveCacertsPath(home)
		if cacerts == "" {
			continue
		}

		output, err := runKeytoolList(keytool, cacerts, password)
		if err != nil {
			log.Printf("certiwise: discovery: keytool list %s: %v", cacerts, err)
			continue
		}

		parsed := parseKeytoolVerboseOutput(output, cacerts)
		remaining := maxItems - len(items)
		if len(parsed) > remaining {
			parsed = parsed[:remaining]
		}
		items = append(items, parsed...)
	}

	return items, meta
}

func capJavaHomes(homes []string, maxJvms int) ([]string, ScanMetadata) {
	meta := ScanMetadata{JavaCacertsJvmTotal: len(homes)}
	if maxJvms <= 0 {
		maxJvms = defaultJavaMaxJvms
	}
	sort.Strings(homes)
	if len(homes) > maxJvms {
		meta.JavaCacertsTruncated = true
		homes = homes[:maxJvms]
	}
	meta.JavaCacertsJvmScanned = len(homes)
	return homes, meta
}

func resolveJavaHomes() []string {
	seen := make(map[string]struct{})
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return
		}
		seen[path] = struct{}{}
	}

	if home := strings.TrimSpace(os.Getenv("JAVA_HOME")); home != "" {
		add(home)
	}

	switch runtime.GOOS {
	case "windows":
		for _, root := range []string{
			os.Getenv("ProgramFiles"),
			os.Getenv("ProgramFiles(x86)"),
		} {
			root = strings.TrimSpace(root)
			if root == "" {
				continue
			}
			javaRoot := filepath.Join(root, "Java")
			entries, err := os.ReadDir(javaRoot)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					add(filepath.Join(javaRoot, entry.Name()))
				}
			}
		}
	default:
		entries, err := os.ReadDir("/usr/lib/jvm")
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					add(filepath.Join("/usr/lib/jvm", entry.Name()))
				}
			}
		}
	}

	homes := make([]string, 0, len(seen))
	for home := range seen {
		homes = append(homes, home)
	}
	return homes
}

func resolveCacertsPath(javaHome string) string {
	candidates := []string{
		filepath.Join(javaHome, "lib", "security", "cacerts"),
		filepath.Join(javaHome, "jre", "lib", "security", "cacerts"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

func resolveJavaStorePassword(configured string) string {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed
	}
	if value := strings.TrimSpace(os.Getenv("JAVA_CACERTS_PASSWORD")); value != "" {
		return value
	}
	return defaultJavaStorePass
}

func runKeytoolList(keytool, keystore, password string) (string, error) {
	cmd := exec.Command(
		keytool,
		"-list",
		"-v",
		"-keystore", keystore,
		"-storepass", password,
	)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func parseKeytoolVerboseOutput(output, keystorePath string) []DiscoveredItem {
	output = strings.ReplaceAll(output, "\r\n", "\n")
	aliasMatches := keytoolAliasPattern.FindAllStringSubmatchIndex(output, -1)
	if len(aliasMatches) == 0 {
		return nil
	}

	items := make([]DiscoveredItem, 0, len(aliasMatches))
	for i, loc := range aliasMatches {
		start := loc[0]
		end := len(output)
		if i+1 < len(aliasMatches) {
			end = aliasMatches[i+1][0]
		}
		block := output[start:end]

		alias := strings.TrimSpace(output[loc[2]:loc[3]])
		shaMatch := keytoolSHA256Pattern.FindStringSubmatch(block)
		if alias == "" || shaMatch == nil {
			continue
		}

		thumbprint := normalizeKeytoolFingerprint(shaMatch[1])
		if len(thumbprint) != 64 {
			continue
		}

		notAfter := ""
		if untilMatch := keytoolUntilPattern.FindStringSubmatch(block); untilMatch != nil {
			notAfter = parseKeytoolNotAfter(strings.TrimSpace(untilMatch[1]))
		}

		items = append(items, DiscoveredItem{
			Source:         SourceJavaCacerts,
			Path:           keystorePath,
			Alias:          alias,
			Thumbprint:     thumbprint,
			NotAfter:       notAfter,
			TrustStoreType: javaCacertsTrustType,
		})
	}

	return items
}

func normalizeKeytoolFingerprint(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
}

func parseKeytoolNotAfter(value string) string {
	layouts := []string{
		time.RFC1123,
		"Mon Jan 2 15:04:05 MST 2006",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}
	return value
}
