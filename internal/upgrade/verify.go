package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// VerifySHA256 checks that data matches the expected lowercase hex digest.
func VerifySHA256(data []byte, expectedHex string) error {
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, strings.TrimSpace(expectedHex)) {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedHex, actual)
	}
	return nil
}
