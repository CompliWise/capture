package java

import (
	"strings"

	"github.com/bluewave-labs/capture/internal/installer"
)

// VerifyKeystoreAlias confirms the alias exists in the keystore.
func VerifyKeystoreAlias(keytool, alias, keystore, password string) error {
	output, err := runKeytoolArgs(ListAliasArgs(keytool, alias, keystore, password))
	if err != nil {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			"keystore alias verification failed",
		)
	}
	if !strings.Contains(output, alias) {
		return installer.NewCodedError(
			"ERR_VERIFY_FAILED",
			"keystore alias verification failed",
		)
	}
	return nil
}
