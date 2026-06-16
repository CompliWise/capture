package database

import (
	"os/exec"

	"github.com/bluewave-labs/capture/internal/installer"
)

type defaultExecutor struct{}

func (defaultExecutor) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func resolveExecutor(opts installer.InstallOptions) installer.CommandExecutor {
	if opts.Executor != nil {
		return opts.Executor
	}
	return defaultExecutor{}
}

func runOrapki(exec installer.CommandExecutor, args ...string) ([]byte, error) {
	return exec.Run("orapki", args...)
}
