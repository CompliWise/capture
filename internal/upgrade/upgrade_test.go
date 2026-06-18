package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		current string
		target  string
		want    int
	}{
		{current: "1.2.0", target: "1.3.0+certiwise.2", want: -1},
		{current: "1.3.0", target: "1.3.0+certiwise.2", want: 0},
		{current: "1.4.0", target: "1.3.0", want: 1},
	}

	for _, tc := range cases {
		if got := CompareVersions(tc.current, tc.target); got != tc.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.current, tc.target, got, tc.want)
		}
	}
}

func TestVerifySHA256Mismatch(t *testing.T) {
	t.Parallel()

	err := VerifySHA256([]byte("tampered"), "00")
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestVerifySHA256Match(t *testing.T) {
	t.Parallel()

	data := []byte("valid-artifact")
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])
	if err := VerifySHA256(data, expected); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestIsMaintenanceWindowOpen(t *testing.T) {
	t.Parallel()

	sundayOpen := time.Date(2026, 6, 14, 3, 0, 0, 0, time.UTC)
	if !IsMaintenanceWindowOpen("Sun 02:00-06:00", sundayOpen) {
		t.Fatal("expected Sunday 03:00 UTC to be inside maintenance window")
	}

	sundayClosed := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)
	if IsMaintenanceWindowOpen("Sun 02:00-06:00", sundayClosed) {
		t.Fatal("expected Sunday 08:00 UTC to be outside maintenance window")
	}

	if !IsMaintenanceWindowOpen("", time.Now()) {
		t.Fatal("empty maintenance window should always be open")
	}
}

type stubArtifactClient struct {
	grant *ArtifactGrant
}

func (s *stubArtifactClient) GetUpgradeArtifact(
	_ context.Context,
	_, _ string,
) (*ArtifactGrant, error) {
	return s.grant, nil
}

func TestRunnerTickChecksumFailure(t *testing.T) {
	t.Parallel()

	data := []byte("artifact-bytes")
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()

	client := &stubArtifactClient{
		grant: &ArtifactGrant{
			DownloadURL: server.URL,
			SHA256:      expected[:62] + "ff",
		},
	}

	runner := NewRunner(Config{BinaryPath: t.TempDir() + "/capture", TempDir: t.TempDir()})
	_, status, err := runner.Tick(
		context.Background(),
		client,
		"1.2.0",
		"linux/amd64",
		PolicyHints{TargetVersion: "1.3.0", MaintenanceWindowUtc: "", Force: true},
	)
	if err == nil {
		t.Fatal("expected checksum verification failure")
	}
	if status != StateFailed {
		t.Fatalf("expected failed state, got %s", status)
	}
}
