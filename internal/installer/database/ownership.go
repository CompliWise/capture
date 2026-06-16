package database

import (
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

const postgresPermissionMessage = "Insufficient privileges to set PostgreSQL root.crt ownership. Run the agent as root or configure dbUser to the agent user."

func applyPostgresOwnership(path, dbUser string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return installer.NewCodedError(
			"ERR_PERMISSION",
			postgresPermissionMessage,
		)
	}

	username := strings.TrimSpace(dbUser)
	if username == "" {
		username = "postgres"
	}

	record, err := user.Lookup(username)
	if err != nil {
		return nil
	}

	uid, uidErr := strconv.Atoi(record.Uid)
	gid, gidErr := strconv.Atoi(record.Gid)
	if uidErr != nil || gidErr != nil {
		return installer.NewCodedError(
			"ERR_PERMISSION",
			postgresPermissionMessage,
		)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return installer.NewCodedError(
			"ERR_PERMISSION",
			postgresPermissionMessage,
		)
	}

	return nil
}
