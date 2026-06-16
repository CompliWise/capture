package runtime

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/bluewave-labs/capture/internal/certiwise"
	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/dotnet"
	"github.com/bluewave-labs/capture/internal/installer/java"
	"github.com/bluewave-labs/capture/internal/installer/linux"
	"github.com/bluewave-labs/capture/internal/installer/macos"
	"github.com/bluewave-labs/capture/internal/installer/node"
	"github.com/bluewave-labs/capture/internal/installer/python"
	installerstate "github.com/bluewave-labs/capture/internal/installer/state"
)

var (
	defaultInstallRegistry = newDefaultInstallRegistry()
	defaultInstallState    = installerstate.NewStore(resolveInstallStatePath())
)

func resolveInstallStatePath() string {
	if value := strings.TrimSpace(os.Getenv("COMPLIWISE_INSTALL_STATE_PATH")); value != "" {
		return value
	}
	return installerstate.DefaultStatePath
}

type assignmentTracker struct {
	mu                   sync.Mutex
	processedDeployments map[string]struct{}
}

func newAssignmentTracker() *assignmentTracker {
	return &assignmentTracker{
		processedDeployments: make(map[string]struct{}),
	}
}

func (t *assignmentTracker) isSucceeded(deploymentID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, seen := t.processedDeployments[deploymentID]
	return seen
}

func (t *assignmentTracker) markSucceeded(deploymentID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.processedDeployments[deploymentID] = struct{}{}
}

func syncAssignments(
	ctx context.Context,
	client *certiwise.Client,
	tracker *assignmentTracker,
) (*certiwise.AssignmentsPullResponse, []certiwise.AssignmentPullItem, error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}

	pull, err := client.PullAssignments()
	if err != nil {
		return nil, nil, fmt.Errorf("pull assignments: %w", err)
	}

	succeeded := make([]certiwise.AssignmentPullItem, 0)
	for _, assignment := range pull.Assignments {
		if tracker.isSucceeded(assignment.DeploymentID) {
			continue
		}

		if err := processAssignment(ctx, client, assignment); err != nil {
			log.Printf(
				"certiwise: assignment %s deployment %s failed: %v",
				assignment.AssignmentID,
				assignment.DeploymentID,
				err,
			)
			continue
		}

		tracker.markSucceeded(assignment.DeploymentID)
		succeeded = append(succeeded, assignment)
	}

	return pull, succeeded, nil
}

func processAssignment(
	ctx context.Context,
	client *certiwise.Client,
	assignment certiwise.AssignmentPullItem,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	finishedAt := certiwise.NowISO()
	report := func(status, errorCode, errorMessage, installerLog string) {
		req := certiwise.DeploymentReportRequest{
			Status:       status,
			ErrorCode:    errorCode,
			ErrorMessage: errorMessage,
			InstallerLog: installer.TruncateLog(installerLog),
			FinishedAt:   finishedAt,
		}
		if err := client.ReportDeployment(assignment.DeploymentID, req); err != nil {
			log.Printf(
				"certiwise: report deployment %s (%s): %v",
				assignment.DeploymentID,
				status,
				err,
			)
		}
	}

	intent := strings.TrimSpace(assignment.DeploymentIntent)
	if intent == "" {
		intent = "install"
	}

	if intent == "remove" {
		return processRemoval(ctx, assignment, report)
	}

	inst, ok := defaultInstallRegistry.Lookup(assignment.TrustStoreType)
	if !ok || !inst.Supports(assignment.MaterialType, assignment.TrustStoreType) {
		message := fmt.Sprintf(
			"trust store type %q is not supported by this agent build",
			assignment.TrustStoreType,
		)
		report("failed", "ERR_UNSUPPORTED_INSTALLER", message, "")
		return fmt.Errorf("%s", message)
	}

	thumbprint, err := installer.ThumbprintFromPEM(assignment.Material.ChainPem)
	if err != nil {
		report("failed", "ERR_INSTALL_FAILED", err.Error(), "")
		return err
	}

	opts := installer.InstallOptions{
		AssignmentID:      assignment.AssignmentID,
		DeploymentID:      assignment.DeploymentID,
		TrustStoreType:    assignment.TrustStoreType,
		MaterialType:      assignment.MaterialType,
		ChainPem:          assignment.Material.ChainPem,
		PrivateKeyPem:     assignment.Material.PrivateKeyPem,
		Thumbprint:        thumbprint,
		CertFileName:      assignment.Config.CertFileName,
		KeyFileName:       assignment.Config.KeyFileName,
		KeyPermissionMode: assignment.Config.KeyPermissionMode,
		TrustStorePath:    assignment.Config.TrustStorePath,
		Alias:             assignment.Config.Alias,
		StorePasswordRef:  assignment.Config.StorePasswordRef,
		JavaHome:          assignment.Config.JavaHome,
		PythonVenvPath:    assignment.Config.PythonVenvPath,
		ReloadCommand:     assignment.Config.ReloadCommand,
		EnvFilePath:       assignment.Config.EnvFilePath,
		StoreLocation:     assignment.Config.StoreLocation,
		StoreName:         assignment.Config.StoreName,
		VerifyEndpoint:    assignment.Config.VerifyEndpoint,
		VerifyServerName:  assignment.Config.VerifyServerName,
		UseOpensslCa:      assignment.Config.UseOpensslCa,
		NodeFlags:         assignment.Config.NodeFlags,
		PreferOsStore:     assignment.Config.PreferOsStore,
		KeychainPath:      assignment.Config.KeychainPath,
		IIS:               mapIISConfig(assignment.Config.IIS),
		Metadata:          &installer.InstallRecord{},
	}

	installerLog, installErr := inst.Install(ctx, opts)
	if installErr != nil {
		errorCode := mapInstallError(installErr)
		report("failed", errorCode, installErr.Error(), installerLog)
		return installErr
	}

	record := buildInstallRecord(assignment, thumbprint, opts)
	if opts.Metadata != nil {
		record = mergeInstallMetadata(record, *opts.Metadata)
	}
	if err := defaultInstallState.Upsert(record); err != nil {
		log.Printf("certiwise: persist install state for %s: %v", assignment.AssignmentID, err)
	}

	report("succeeded", "", "", installerLog)
	log.Printf(
		"certiwise: installed %s material for assignment %s",
		assignment.MaterialType,
		assignment.AssignmentID,
	)
	return nil
}

func mapInstallError(err error) string {
	if code := installer.ErrorCode(err); code != "" {
		return code
	}
	return "ERR_INSTALL_FAILED"
}

func processRemoval(
	ctx context.Context,
	assignment certiwise.AssignmentPullItem,
	report func(status, errorCode, errorMessage, installerLog string),
) error {
	record, ok := defaultInstallState.Get(assignment.AssignmentID)
	if !ok {
		message := fmt.Sprintf("no install state for assignment %s", assignment.AssignmentID)
		report("failed", "ERR_REMOVAL_FAILED", message, "")
		return fmt.Errorf("%s", message)
	}

	inst, found := defaultInstallRegistry.Lookup(assignment.TrustStoreType)
	if !found || !inst.Supports(assignment.MaterialType, assignment.TrustStoreType) {
		message := fmt.Sprintf(
			"trust store type %q is not supported by this agent build",
			assignment.TrustStoreType,
		)
		report("failed", "ERR_UNSUPPORTED_INSTALLER", message, "")
		return fmt.Errorf("%s", message)
	}

	installerLog, err := inst.Remove(ctx, installer.RemoveOptions{
		AssignmentID:   assignment.AssignmentID,
		TrustStoreType: assignment.TrustStoreType,
		Record:         record,
	})
	if err != nil {
		report("failed", "ERR_REMOVAL_FAILED", err.Error(), installerLog)
		return err
	}

	if err := defaultInstallState.Delete(assignment.AssignmentID); err != nil {
		log.Printf("certiwise: delete install state for %s: %v", assignment.AssignmentID, err)
	}

	report("removed", "", "", installerLog)
	log.Printf("certiwise: removed trust material for assignment %s", assignment.AssignmentID)
	return nil
}

func buildInstallRecord(
	assignment certiwise.AssignmentPullItem,
	thumbprint string,
	opts installer.InstallOptions,
) installer.InstallRecord {
	record := installer.InstallRecord{
		AssignmentID:   assignment.AssignmentID,
		TrustStoreType: assignment.TrustStoreType,
		Thumbprint:     thumbprint,
		Alias:          installer.DefaultAlias(assignment.AssignmentID, assignment.Config.Alias),
		TrustStorePath: strings.TrimSpace(assignment.Config.TrustStorePath),
		EnvFilePath:    strings.TrimSpace(assignment.Config.EnvFilePath),
	}

	switch assignment.TrustStoreType {
	case "linux_update_ca_certificates":
		record.CertPath = linux.CertPathForOptions(linux.InstallOptions{
			AssignmentID:   assignment.AssignmentID,
			CertFileName:   opts.CertFileName,
			TrustStorePath: opts.TrustStorePath,
			Alias:          opts.Alias,
		})
	case "java_cacerts", "java_pkcs12":
		record.CertPath, record.TrustStorePath = java.RecordPaths(opts)
		record.Alias = java.KeytoolAlias(assignment.AssignmentID, assignment.Config.Alias)
		if assignment.TrustStoreType == "java_pkcs12" && assignment.MaterialType == "server_identity" {
			record.KeyPath = record.TrustStorePath
		}
	case "python_certifi_bundle":
		if path, err := python.ResolveBundlePath(opts.TrustStorePath, opts.PythonVenvPath); err == nil {
			record.CertPath = path
		}
	case "node_extra_ca_certs":
		if path, err := node.BundlePath(opts.TrustStorePath, assignment.AssignmentID, opts.Alias); err == nil {
			record.CertPath = path
			record.TrustStorePath = node.ResolveTrustStorePath(opts.TrustStorePath)
		}
		record.EnvFilePath = strings.TrimSpace(opts.EnvFilePath)
	case "dotnet_root_store":
		record.PreferOsStore = assignment.Config.PreferOsStore
		if assignment.Config.PreferOsStore {
			if runtime.GOOS == "windows" {
				storeName := strings.TrimSpace(assignment.Config.StoreName)
				if storeName == "" {
					storeName = "Root"
				}
				record.StoreName = storeName
				record.CertPath = fmt.Sprintf(`Cert:\LocalMachine\%s\%s`, storeName, strings.ToUpper(thumbprint))
			} else if path := linux.CertPathForOptions(linux.InstallOptions{
				AssignmentID:   assignment.AssignmentID,
				CertFileName:   opts.CertFileName,
				TrustStorePath: opts.TrustStorePath,
				Alias:          opts.Alias,
			}); path != "" {
				record.CertPath = path
			}
		} else if path, err := dotnet.ResolveBundlePath(opts.TrustStorePath); err == nil {
			record.CertPath = path
			record.TrustStorePath = path
		}
		record.EnvFilePath = strings.TrimSpace(opts.EnvFilePath)
	case "pem_directory":
		storePath := strings.TrimSpace(opts.TrustStorePath)
		certName := strings.TrimSpace(opts.CertFileName)
		if certName == "" {
			certName = "tls.crt"
		} else {
			certName = installer.SanitizeFileName(certName)
		}
		record.CertPath = filepath.Join(storePath, certName)
		if assignment.MaterialType == "server_identity" {
			keyName := strings.TrimSpace(opts.KeyFileName)
			if keyName == "" {
				keyName = "tls.key"
			} else {
				keyName = installer.SanitizeFileName(keyName)
			}
			record.KeyPath = filepath.Join(storePath, keyName)
		}
	case "macos_keychain_system":
		if path, err := macos.ResolveKeychainPath(opts.KeychainPath); err == nil {
			record.KeychainPath = path
		} else if path, err := macos.ResolveKeychainPath(assignment.Config.KeychainPath); err == nil {
			record.KeychainPath = path
		}
		record.Alias = installer.DefaultAlias(assignment.AssignmentID, assignment.Config.Alias)
	case "windows_cert_store":
		storeName := strings.TrimSpace(assignment.Config.StoreName)
		if storeName == "" {
			if assignment.MaterialType == "server_identity" {
				storeName = "My"
			} else {
				storeName = "Root"
			}
		}
		record.StoreName = storeName
		record.CertPath = fmt.Sprintf(`Cert:\LocalMachine\%s\%s`, storeName, strings.ToUpper(thumbprint))
		if assignment.Config.IIS != nil {
			record.IISSiteName = strings.TrimSpace(assignment.Config.IIS.SiteName)
			record.IISBindingHost = strings.TrimSpace(assignment.Config.IIS.BindingHost)
			if assignment.Config.IIS.BindingPort > 0 {
				record.IISBindingPort = assignment.Config.IIS.BindingPort
			} else {
				record.IISBindingPort = 443
			}
		}
	}

	return record
}

func mapIISConfig(config *certiwise.IISAssignmentConfig) installer.IISConfig {
	if config == nil {
		return installer.IISConfig{}
	}
	return installer.IISConfig{
		SiteName:    config.SiteName,
		BindingHost: config.BindingHost,
		BindingPort: config.BindingPort,
		IPAddress:   config.IPAddress,
		SNI:         config.SNI,
	}
}

func mergeInstallMetadata(base, runtime installer.InstallRecord) installer.InstallRecord {
	if strings.TrimSpace(runtime.Thumbprint) != "" {
		base.Thumbprint = runtime.Thumbprint
	}
	if strings.TrimSpace(runtime.CertPath) != "" {
		base.CertPath = runtime.CertPath
	}
	if strings.TrimSpace(runtime.StoreName) != "" {
		base.StoreName = runtime.StoreName
	}
	if strings.TrimSpace(runtime.BindingSnapshotThumbprint) != "" {
		base.BindingSnapshotThumbprint = runtime.BindingSnapshotThumbprint
	}
	if strings.TrimSpace(runtime.IISSiteName) != "" {
		base.IISSiteName = runtime.IISSiteName
	}
	if strings.TrimSpace(runtime.IISBindingHost) != "" {
		base.IISBindingHost = runtime.IISBindingHost
	}
	if runtime.IISBindingPort > 0 {
		base.IISBindingPort = runtime.IISBindingPort
	}
	if runtime.PreferOsStore {
		base.PreferOsStore = true
	}
	if strings.TrimSpace(runtime.EnvFilePath) != "" {
		base.EnvFilePath = runtime.EnvFilePath
	}
	if strings.TrimSpace(runtime.TrustStorePath) != "" {
		base.TrustStorePath = runtime.TrustStorePath
	}
	if strings.TrimSpace(runtime.KeychainPath) != "" {
		base.KeychainPath = runtime.KeychainPath
	}
	if strings.TrimSpace(runtime.CertCommonName) != "" {
		base.CertCommonName = runtime.CertCommonName
	}
	return base
}

