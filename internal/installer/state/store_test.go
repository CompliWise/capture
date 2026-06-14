package state

import (
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
)

func TestStoreUpsertDelete(t *testing.T) {
	path := t.TempDir() + "/install-state.json"
	store := NewStore(path)

	record := installer.InstallRecord{
		AssignmentID:   "assign-1",
		TrustStoreType: "linux_update_ca_certificates",
		Thumbprint:     "abc",
		CertPath:       "/tmp/cert.crt",
	}

	if err := store.Upsert(record); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, ok := store.Get("assign-1")
	if !ok || got.CertPath != record.CertPath {
		t.Fatalf("expected stored record, got %+v ok=%v", got, ok)
	}

	if err := store.Delete("assign-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, ok := store.Get("assign-1"); ok {
		t.Fatal("expected record deleted")
	}
}
