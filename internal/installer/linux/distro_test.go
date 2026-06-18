package linux

import (
	"os"
	"testing"
)

func TestParseOSReleaseDebian(t *testing.T) {
	content := `ID=debian
ID_LIKE=debian
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"`
	if got := ParseOSRelease(content); got != DistroDebian {
		t.Fatalf("expected debian, got %q", got)
	}
}

func TestParseOSReleaseUbuntu(t *testing.T) {
	content := `ID=ubuntu
ID_LIKE=debian`
	if got := ParseOSRelease(content); got != DistroDebian {
		t.Fatalf("expected debian family, got %q", got)
	}
}

func TestParseOSReleaseRHEL(t *testing.T) {
	for _, fixture := range []string{
		`ID=rocky
ID_LIKE="rhel centos fedora"`,
		`ID=rhel
ID_LIKE="fedora"`,
		`ID=centos
ID_LIKE="rhel fedora"`,
	} {
		if got := ParseOSRelease(fixture); got != DistroRHEL {
			t.Fatalf("expected rhel for %q, got %q", fixture, got)
		}
	}
}

func TestParseOSReleaseSUSE(t *testing.T) {
	content := `ID=opensuse-leap
ID_LIKE="suse"`
	if got := ParseOSRelease(content); got != DistroSUSE {
		t.Fatalf("expected suse, got %q", got)
	}
}

func TestParseOSReleaseAlpine(t *testing.T) {
	content := `ID=alpine
ID_LIKE=`
	if got := ParseOSRelease(content); got != DistroAlpine {
		t.Fatalf("expected alpine, got %q", got)
	}
}

func TestProfileForPaths(t *testing.T) {
	tests := []struct {
		kind       DistroKind
		installDir string
		ext        string
		bundle     string
	}{
		{DistroDebian, "/usr/local/share/ca-certificates", ".crt", "/etc/ssl/certs/ca-certificates.crt"},
		{DistroRHEL, "/etc/pki/ca-trust/source/anchors", ".crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"},
		{DistroSUSE, "/etc/pki/trust/anchors", ".pem", "/etc/ssl/ca-bundle.pem"},
		{DistroAlpine, "/usr/local/share/ca-certificates", ".crt", "/etc/ssl/cert.pem"},
	}

	for _, tc := range tests {
		profile := ProfileFor(tc.kind)
		if profile.InstallDir != tc.installDir {
			t.Fatalf("%s install dir: got %q want %q", tc.kind, profile.InstallDir, tc.installDir)
		}
		if profile.FileExt != tc.ext {
			t.Fatalf("%s ext: got %q want %q", tc.kind, profile.FileExt, tc.ext)
		}
		if profile.BundlePath != tc.bundle {
			t.Fatalf("%s bundle: got %q want %q", tc.kind, profile.BundlePath, tc.bundle)
		}
	}
}

func TestProfileFromPathRHEL(t *testing.T) {
	profile := ProfileFromPath("/etc/pki/ca-trust/source/anchors")
	if profile.Kind != DistroRHEL {
		t.Fatalf("expected rhel profile, got %q", profile.Kind)
	}
}

func TestDetectDistroFromFixture(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/os-release"
	if err := os.WriteFile(path, []byte("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	kind, err := DetectDistro(path)
	if err != nil {
		t.Fatalf("DetectDistro: %v", err)
	}
	if kind != DistroRHEL {
		t.Fatalf("expected rocky -> rhel, got %q", kind)
	}
}

func TestUpdateCommandsForCertPathRHEL(t *testing.T) {
	commands := UpdateCommandsForCertPath("/etc/pki/ca-trust/source/anchors/compliwise-internal-ca.crt")
	if len(commands) != 1 || commands[0][0] != "update-ca-trust" {
		t.Fatalf("unexpected commands: %#v", commands)
	}
}
