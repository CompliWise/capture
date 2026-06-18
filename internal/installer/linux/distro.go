package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DistroKind identifies a supported Linux distribution family.
type DistroKind string

const (
	DistroDebian  DistroKind = "debian"
	DistroRHEL    DistroKind = "rhel"
	DistroSUSE    DistroKind = "suse"
	DistroAlpine  DistroKind = "alpine"
	DistroUnknown DistroKind = "unknown"
)

const defaultOSReleasePath = "/etc/os-release"

// DistroProfile describes anchor install paths and trust refresh commands.
type DistroProfile struct {
	Kind           DistroKind
	InstallDir     string
	FileExt        string
	BundlePath     string
	UpdateCommands [][]string
}

// ParseOSRelease maps os-release content to a distro kind.
func ParseOSRelease(content string) DistroKind {
	values := parseOSReleaseValues(content)
	id := strings.ToLower(strings.TrimSpace(values["ID"]))
	idLike := strings.ToLower(strings.TrimSpace(values["ID_LIKE"]))

	if id == "alpine" {
		return DistroAlpine
	}

	if containsToken(id, "debian", "ubuntu") || containsToken(idLike, "debian") {
		return DistroDebian
	}

	if containsToken(id, "rhel", "centos", "rocky", "alma", "ol", "fedora") ||
		containsToken(idLike, "rhel", "fedora", "centos") {
		return DistroRHEL
	}

	if containsToken(id, "opensuse-leap", "opensuse-tumbleweed", "sles", "suse") {
		return DistroSUSE
	}

	if id == "" {
		return DistroUnknown
	}

	return DistroDebian
}

func parseOSReleaseValues(content string) map[string]string {
	values := make(map[string]string)
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return values
}

func containsToken(haystack string, needles ...string) bool {
	if haystack == "" {
		return false
	}
	for _, part := range strings.Fields(strings.ReplaceAll(haystack, ",", " ")) {
		for _, needle := range needles {
			if part == needle {
				return true
			}
		}
	}
	return false
}

// DetectDistro reads os-release from the given path and returns the distro kind.
func DetectDistro(osReleasePath string) (DistroKind, error) {
	path := strings.TrimSpace(osReleasePath)
	if path == "" {
		path = defaultOSReleasePath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return DistroUnknown, fmt.Errorf("read os-release: %w", err)
	}

	kind := ParseOSRelease(string(data))
	if kind == DistroUnknown {
		return DistroDebian, nil
	}
	return kind, nil
}

// ProfileFor returns install metadata for a distro kind.
func ProfileFor(kind DistroKind) DistroProfile {
	switch kind {
	case DistroRHEL:
		return DistroProfile{
			Kind:       DistroRHEL,
			InstallDir: "/etc/pki/ca-trust/source/anchors",
			FileExt:    ".crt",
			BundlePath: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
			UpdateCommands: [][]string{
				{"update-ca-trust", "extract"},
			},
		}
	case DistroSUSE:
		return DistroProfile{
			Kind:       DistroSUSE,
			InstallDir: "/etc/pki/trust/anchors",
			FileExt:    ".pem",
			BundlePath: "/etc/ssl/ca-bundle.pem",
			UpdateCommands: [][]string{
				{"update-ca-certificates"},
				{"trust", "extract"},
			},
		}
	case DistroAlpine:
		return DistroProfile{
			Kind:       DistroAlpine,
			InstallDir: defaultLinuxCAPath,
			FileExt:    ".crt",
			BundlePath: "/etc/ssl/cert.pem",
			UpdateCommands: [][]string{
				{"update-ca-certificates"},
			},
		}
	case DistroDebian:
		return debianFamilyProfile(DistroDebian)
	case DistroUnknown:
		return debianFamilyProfile(DistroUnknown)
	default:
		return debianFamilyProfile(DistroDebian)
	}
}

func debianFamilyProfile(kind DistroKind) DistroProfile {
	return DistroProfile{
		Kind:       kind,
		InstallDir: defaultLinuxCAPath,
		FileExt:    ".crt",
		BundlePath: "/etc/ssl/certs/ca-certificates.crt",
		UpdateCommands: [][]string{
			{"update-ca-certificates"},
		},
	}
}

// ProfileFromPath infers a distro profile from a configured anchor directory.
func ProfileFromPath(storePath string) DistroProfile {
	cleaned := filepath.Clean(strings.TrimSpace(storePath))
	switch cleaned {
	case "/etc/pki/ca-trust/source/anchors":
		return ProfileFor(DistroRHEL)
	case "/etc/pki/trust/anchors":
		return ProfileFor(DistroSUSE)
	default:
		if strings.HasSuffix(cleaned, "/anchors") && strings.Contains(cleaned, "ca-trust") {
			return ProfileFor(DistroRHEL)
		}
		return ProfileFor(DistroDebian)
	}
}

// UpdateCommandsForCertPath returns refresh commands for an installed anchor path.
func UpdateCommandsForCertPath(certPath string) [][]string {
	dir := filepath.Clean(filepath.Dir(strings.TrimSpace(certPath)))
	return ProfileFromPath(dir).UpdateCommands
}
