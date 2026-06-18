package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/compliwise/capture/internal/installer"
)

// DefaultStatePath is the default install-state file location.
const DefaultStatePath = "/var/lib/compliwise/install-state.json"

// Store persists install records for remove-on-revoke.
type Store struct {
	path string
}

// NewStore creates a store at the given path.
func NewStore(path string) *Store {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		trimmed = DefaultStatePath
	}
	return &Store{path: filepath.Clean(trimmed)}
}

// Load reads all install records from disk.
func (s *Store) Load() (map[string]installer.InstallRecord, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]installer.InstallRecord{}, nil
		}
		return nil, fmt.Errorf("read install state: %w", err)
	}

	records := make(map[string]installer.InstallRecord)
	if len(data) == 0 {
		return records, nil
	}

	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse install state: %w", err)
	}

	return records, nil
}

// Upsert saves or updates one install record.
func (s *Store) Upsert(record installer.InstallRecord) error {
	records, err := s.Load()
	if err != nil {
		return err
	}

	records[record.AssignmentID] = record
	return s.save(records)
}

// Delete removes an install record.
func (s *Store) Delete(assignmentID string) error {
	records, err := s.Load()
	if err != nil {
		return err
	}

	delete(records, assignmentID)
	return s.save(records)
}

// Get returns one record if present.
func (s *Store) Get(assignmentID string) (installer.InstallRecord, bool) {
	records, err := s.Load()
	if err != nil {
		return installer.InstallRecord{}, false
	}
	record, ok := records[assignmentID]
	return record, ok
}

func (s *Store) save(records map[string]installer.InstallRecord) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create install state directory: %w", err)
	}

	payload, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal install state: %w", err)
	}

	if err := os.WriteFile(s.path, payload, 0o600); err != nil {
		return fmt.Errorf("write install state: %w", err)
	}

	return nil
}
