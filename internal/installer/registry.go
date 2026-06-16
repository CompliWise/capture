package installer

import "sync"

// Registry maps trustStoreType values to Installer implementations.
type Registry struct {
	mu         sync.RWMutex
	installers map[string]Installer
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		installers: make(map[string]Installer),
	}
}

// Register adds an installer for its supported trust store types.
func (r *Registry) Register(inst Installer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, trustStoreType := range []string{
		"linux_update_ca_certificates",
		"java_cacerts",
		"java_pkcs12",
		"python_certifi_bundle",
		"node_extra_ca_certs",
		"dotnet_root_store",
		"pem_directory",
		"windows_cert_store",
	} {
		if inst.Supports("trust_anchor", trustStoreType) {
			r.installers[trustStoreType] = inst
		}
	}
}

// Lookup returns the installer for a trust store type.
func (r *Registry) Lookup(trustStoreType string) (Installer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	inst, ok := r.installers[trustStoreType]
	return inst, ok
}
