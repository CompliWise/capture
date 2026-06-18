package runtime

import (
	"github.com/compliwise/capture/internal/installer"
	"github.com/compliwise/capture/internal/installer/database"
	"github.com/compliwise/capture/internal/installer/dotnet"
	"github.com/compliwise/capture/internal/installer/java"
	"github.com/compliwise/capture/internal/installer/linux"
	"github.com/compliwise/capture/internal/installer/macos"
	"github.com/compliwise/capture/internal/installer/mainframe"
	"github.com/compliwise/capture/internal/installer/node"
	"github.com/compliwise/capture/internal/installer/pem"
	"github.com/compliwise/capture/internal/installer/python"
	wininstaller "github.com/compliwise/capture/internal/installer/windows"
)

func newDefaultInstallRegistry() *installer.Registry {
	registry := installer.NewRegistry()
	registry.Register(&linux.Installer{})
	registry.Register(&java.Installer{})
	registry.Register(&python.Installer{})
	registry.Register(&node.Installer{})
	registry.Register(&dotnet.Installer{})
	registry.Register(&pem.Installer{})
	registry.Register(&wininstaller.Installer{})
	registry.Register(&macos.Installer{})
	registry.Register(&database.Installer{})
	registry.Register(&mainframe.Installer{})
	return registry
}
