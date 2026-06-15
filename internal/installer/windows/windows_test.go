package windows

import (
	"runtime"
	"strings"
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/testfixtures"
)

type mockCommandExecutor struct {
	calls []string
	fn    func(callIndex int, name string, args ...string) ([]byte, error)
}

func (m *mockCommandExecutor) Run(name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	m.calls = append(m.calls, call)
	if m.fn != nil {
		return m.fn(len(m.calls)-1, name, args...)
	}
	return []byte("OK"), nil
}

func TestTrustAnchorImportScript(t *testing.T) {
	executor := &mockCommandExecutor{}
	thumbprint, err := installer.ThumbprintFromPEM(testfixtures.SampleTrustAnchorPEM)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	log, err := installTrustAnchor(installer.InstallOptions{
		ChainPem:   testfixtures.SampleTrustAnchorPEM,
		Thumbprint: thumbprint,
		Executor:   executor,
	}, executor)
	if err != nil {
		t.Fatalf("installTrustAnchor: %v\nlog: %s", err, log)
	}

	if len(executor.calls) != 1 {
		t.Fatalf("expected 1 powershell call, got %d", len(executor.calls))
	}
	if !strings.Contains(executor.calls[0], "Import-Certificate") {
		t.Fatalf("expected Import-Certificate in %q", executor.calls[0])
	}
	if !strings.Contains(executor.calls[0], `Cert:\LocalMachine\Root`) {
		t.Fatalf("expected Root store in %q", executor.calls[0])
	}
}

func TestIISIdentityBindingUpdate(t *testing.T) {
	pair := testfixtures.GenerateServerIdentityPEM(t)
	thumbprint, err := installer.ThumbprintFromPEM(pair.ChainPem)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	executor := &mockCommandExecutor{
		fn: func(callIndex int, _ string, args ...string) ([]byte, error) {
			script := args[len(args)-1]
			switch callIndex {
			case 0:
				if !strings.Contains(script, "CreateFromPemFile") {
					t.Fatalf("expected CreateFromPemFile, got %q", script)
				}
				return []byte("imported"), nil
			case 1:
				if !strings.Contains(script, "Get-Item") {
					t.Fatalf("expected binding snapshot script, got %q", script)
				}
				return []byte("OLDTHUMB"), nil
			case 2:
				if !strings.Contains(script, "WebAdministration") {
					t.Fatalf("expected WebAdministration binding update, got %q", script)
				}
				if !strings.Contains(script, "Default Web Site") {
					t.Fatalf("expected site name in script, got %q", script)
				}
				return []byte("binding updated"), nil
			default:
				return []byte("OK"), nil
			}
		},
	}

	metadata := &installer.InstallRecord{}
	log, record, err := installIISIdentity(installer.InstallOptions{
		AssignmentID:   "assign-iis",
		TrustStoreType: "windows_cert_store",
		MaterialType:   "server_identity",
		ChainPem:       pair.ChainPem,
		PrivateKeyPem:  pair.PrivateKeyPem,
		Thumbprint:     thumbprint,
		Alias:          "payment-api-tls",
		IIS: installer.IISConfig{
			SiteName:    "Default Web Site",
			BindingHost: "payment.example.com",
			BindingPort: 443,
			SNI:         true,
		},
		Executor: executor,
		Metadata: metadata,
	}, executor)
	if err != nil {
		t.Fatalf("installIISIdentity: %v\nlog: %s", err, log)
	}
	if record.IISSiteName != "Default Web Site" {
		t.Fatalf("unexpected site name %q", record.IISSiteName)
	}
	if record.BindingSnapshotThumbprint != "OLDTHUMB" {
		t.Fatalf("expected prior binding snapshot, got %q", record.BindingSnapshotThumbprint)
	}
	if metadata.IISSiteName != "Default Web Site" {
		t.Fatalf("metadata not populated")
	}
}

func TestPlatformMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("platform mismatch is only enforced on non-Windows hosts")
	}
	_, err := installTrustAnchor(installer.InstallOptions{
		ChainPem: testfixtures.SampleTrustAnchorPEM,
	}, defaultExecutor{})
	if err == nil {
		t.Fatal("expected platform mismatch error")
	}
	if installer.ErrorCode(err) != "ERR_PLATFORM_MISMATCH" {
		t.Fatalf("expected ERR_PLATFORM_MISMATCH, got %q", installer.ErrorCode(err))
	}
}

func TestPermissionErrorMapping(t *testing.T) {
	executor := &mockCommandExecutor{
		fn: func(_ int, _ string, _ ...string) ([]byte, error) {
			return []byte("Access is denied"), errAccessDenied
		},
	}

	_, err := installTrustAnchor(installer.InstallOptions{
		ChainPem: testfixtures.SampleTrustAnchorPEM,
		Executor: executor,
	}, executor)
	if installer.ErrorCode(err) != "ERR_PERMISSION" {
		t.Fatalf("expected ERR_PERMISSION, got %q", installer.ErrorCode(err))
	}
}

func TestIISSiteNotFound(t *testing.T) {
	pair := testfixtures.GenerateServerIdentityPEM(t)
	executor := &mockCommandExecutor{
		fn: func(callIndex int, _ string, _ ...string) ([]byte, error) {
			if callIndex == 0 {
				return []byte("imported"), nil
			}
			if callIndex == 1 {
				return []byte("ABCDEF"), nil
			}
			return []byte("Cannot find path because site not found"), errSiteNotFound
		},
	}

	_, _, err := installIISIdentity(installer.InstallOptions{
		MaterialType:  "server_identity",
		ChainPem:      pair.ChainPem,
		PrivateKeyPem: pair.PrivateKeyPem,
		IIS: installer.IISConfig{
			SiteName:    "Missing Site",
			BindingHost: "payment.example.com",
			BindingPort: 443,
			SNI:         true,
		},
		Executor: executor,
	}, executor)
	if installer.ErrorCode(err) != "ERR_IIS_SITE_NOT_FOUND" {
		t.Fatalf("expected ERR_IIS_SITE_NOT_FOUND, got %q", installer.ErrorCode(err))
	}
}

func TestLogRedaction(t *testing.T) {
	log := SanitizeInstallerLog("before\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\nafter")
	if strings.Contains(log, "BEGIN PRIVATE KEY") {
		t.Fatalf("private key not redacted: %q", log)
	}
	if !strings.Contains(log, "[private key redacted]") {
		t.Fatalf("expected redaction marker in %q", log)
	}
}

func TestInstallerSupports(t *testing.T) {
	inst := Installer{}
	if !inst.Supports("trust_anchor", "windows_cert_store") {
		t.Fatal("expected trust_anchor support")
	}
	if !inst.Supports("server_identity", "windows_cert_store") {
		t.Fatal("expected server_identity support")
	}
	if inst.Supports("trust_anchor", "linux_update_ca_certificates") {
		t.Fatal("unexpected linux support")
	}
}

var (
	errAccessDenied = &execError{msg: "exit status 1"}
	errSiteNotFound = &execError{msg: "site not found"}
)

type execError struct {
	msg string
}

func (e *execError) Error() string {
	return e.msg
}
