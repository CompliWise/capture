package runtime

import (
	"github.com/bluewave-labs/capture/internal/installer"
	"github.com/bluewave-labs/capture/internal/installer/dotnet"
	"github.com/bluewave-labs/capture/internal/installer/java"
	"github.com/bluewave-labs/capture/internal/installer/linux"
	"github.com/bluewave-labs/capture/internal/installer/node"
	"github.com/bluewave-labs/capture/internal/installer/pem"
	"github.com/bluewave-labs/capture/internal/installer/python"
	wininstaller "github.com/bluewave-labs/capture/internal/installer/windows"
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
	return registry
}
