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
	PreferOsStore             bool   `json:"preferOsStore,omitempty"`
	StoreName                 string `json:"storeName,omitempty"`
	BindingSnapshotThumbprint string `json:"bindingSnapshotThumbprint,omitempty"`
	IISSiteName               string `json:"iisSiteName,omitempty"`
	IISBindingHost            string `json:"iisBindingHost,omitempty"`
	IISBindingPort            int    `json:"iisBindingPort,omitempty"`
}

// IISConfig configures IIS HTTPS binding for Windows server identity installs.
type IISConfig struct {
	SiteName     string
	BindingHost  string
	BindingPort  int
	IPAddress    string
	SNI          bool
}

// CommandExecutor runs external commands (test injection for Windows installers).
type CommandExecutor interface {
	Run(name string, args ...string) ([]byte, error)
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
	StorePasswordRef  string
	JavaHome          string
	PythonVenvPath    string
	EnvFilePath       string
	StoreLocation     string
	StoreName         string
	IIS               IISConfig
	VerifyEndpoint    string
	VerifyServerName  string
	UseOpensslCa      bool
	NodeFlags         []string
	PreferOsStore     bool
	Executor          CommandExecutor
	// Metadata is populated by installers that capture runtime rollback fields.
	Metadata          *InstallRecord
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
