package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

type mockCommandExecutor struct {
	output []byte
}

func (m mockCommandExecutor) Run(_ string, _ ...string) ([]byte, error) {
	return m.output, nil
}

func TestParsePowerShellCertJSON(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "powershell-certs.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	items, err := parsePowerShellCertJSON(data, defaultWindowsStoreRoot)
	if err != nil {
		t.Fatalf("parsePowerShellCertJSON: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Source != SourceWindowsCertStore {
		t.Fatalf("expected windows_cert_store source, got %q", items[0].Source)
	}
	if items[0].SubjectCN != "Windows Test Root CA" {
		t.Fatalf("expected subject CN, got %q", items[0].SubjectCN)
	}
	if len(items[0].Thumbprint) != 64 {
		t.Fatalf("expected 64-char thumbprint, got %q", items[0].Thumbprint)
	}
}

func TestScanWindowsCertStoreWithMockExecutor(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "powershell-certs.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	executor := mockCommandExecutor{output: fixture}

	items := ScanWindowsCertStore(WindowsScanOptions{
		Enabled:  true,
		Executor: executor,
	}, 10)
	if len(items) != 2 {
		t.Fatalf("expected 2 windows items, got %d", len(items))
	}
	if items[0].TrustStoreType != SourceWindowsCertStore {
		t.Fatalf("expected trust store type windows_cert_store, got %q", items[0].TrustStoreType)
	}
}

func TestScanWindowsStubWithoutExecutorReturnsEmpty(t *testing.T) {
	items := ScanWindowsCertStore(WindowsScanOptions{Enabled: true}, 10)
	if len(items) != 0 {
		t.Fatalf("expected empty stub result on non-windows without executor, got %d", len(items))
	}
}

func TestNormalizeWindowsThumbprint(t *testing.T) {
	got := normalizeWindowsThumbprint("DE:AD:BE:EF")
	if got != "deadbeef" {
		t.Fatalf("unexpected normalized thumbprint: %q", got)
	}
}

func TestParsePowerShellCertJSONObject(t *testing.T) {
	single := `{"Thumbprint":"DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF","Subject":"CN=Single Root","NotAfter":"2027-01-01T00:00:00Z"}`
	items, err := parsePowerShellCertJSON([]byte(single), defaultWindowsStoreRoot)
	if err != nil {
		t.Fatalf("parsePowerShellCertJSON: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].SubjectCN != "Single Root" {
		t.Fatalf("expected subject CN, got %q", items[0].SubjectCN)
	}
}

func TestScanWindowsCertStoreIncludeMy(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "powershell-certs.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	calls := 0
	executor := mockCommandExecutorFunc(func(_ string, _ ...string) ([]byte, error) {
		calls++
		return fixture, nil
	})

	items := ScanWindowsCertStore(WindowsScanOptions{
		Enabled:   true,
		IncludeMy: true,
		Executor:  executor,
	}, 10)
	if calls != 2 {
		t.Fatalf("expected scans for Root and My stores, got %d calls", calls)
	}
	if len(items) != 4 {
		t.Fatalf("expected 4 combined items, got %d", len(items))
	}
}

func TestExtractSubjectCNWithoutPrefix(t *testing.T) {
	if got := extractSubjectCN("plain-subject"); got != "plain-subject" {
		t.Fatalf("expected plain subject, got %q", got)
	}
}

type mockCommandExecutorFunc func(name string, args ...string) ([]byte, error)

func (f mockCommandExecutorFunc) Run(name string, args ...string) ([]byte, error) {
	return f(name, args...)
}

func TestScanWindowsCertStoreExecutorError(t *testing.T) {
	executor := mockCommandExecutorFunc(func(_ string, _ ...string) ([]byte, error) {
		return nil, os.ErrNotExist
	})

	items := ScanWindowsCertStore(WindowsScanOptions{
		Enabled:  true,
		Executor: executor,
	}, 10)
	if len(items) != 0 {
		t.Fatalf("expected no items on executor error, got %d", len(items))
	}
}

func TestScanWindowsCertStoreInvalidJSON(t *testing.T) {
	executor := mockCommandExecutorFunc(func(_ string, _ ...string) ([]byte, error) {
		return []byte("not-json"), nil
	})

	items := ScanWindowsCertStore(WindowsScanOptions{
		Enabled:  true,
		Executor: executor,
	}, 10)
	if len(items) != 0 {
		t.Fatalf("expected no items on parse error, got %d", len(items))
	}
}

func TestScanWindowsCertStoreRespectsMaxItems(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "powershell-certs.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	executor := mockCommandExecutorFunc(func(_ string, _ ...string) ([]byte, error) {
		return fixture, nil
	})

	items := ScanWindowsCertStore(WindowsScanOptions{
		Enabled:  true,
		Executor: executor,
	}, 1)
	if len(items) != 1 {
		t.Fatalf("expected 1 item due to maxItems cap, got %d", len(items))
	}
}
