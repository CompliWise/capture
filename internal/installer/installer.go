package installer

import "context"

// InstallRecord captures filesystem metadata needed for rollback.
type InstallRecord struct {
	AssignmentID   string `json:"assignmentId"`
	TrustStoreType string `json:"trustStoreType"`
	Thumbprint     string `json:"thumbprint"`
	CertPath       string `json:"certPath"`
	KeyPath        string `json:"keyPath,omitempty"`
	Alias          string `json:"alias,omitempty"`
	TrustStorePath string `json:"trustStorePath,omitempty"`
	EnvFilePath    string `json:"envFilePath,omitempty"`
}

// InstallOptions configures a trust-store install attempt.
type InstallOptions struct {
	AssignmentID   string
	DeploymentID   string
	TrustStoreType string
	MaterialType      string
	ChainPem          string
	PrivateKeyPem     string
	Thumbprint        string
	CertFileName      string
	KeyFileName       string
	KeyPermissionMode string
	TrustStorePath    string
	Alias             string
	ReloadCommand     []string
	StorePassword     string
	EnvFilePath       string
}

// RemoveOptions configures a trust-store removal attempt.
type RemoveOptions struct {
	AssignmentID   string
	TrustStoreType string
	Record           InstallRecord
}

// Installer installs and removes trust material for one trust-store type.
type Installer interface {
	Install(ctx context.Context, opts InstallOptions) (string, error)
	Remove(ctx context.Context, opts RemoveOptions) (string, error)
	Supports(materialType, trustStoreType string) bool
}
