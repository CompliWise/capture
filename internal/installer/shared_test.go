package installer

import (
	"errors"
	"testing"

	"github.com/compliwise/capture/internal/installer/testfixtures"
)

func TestValidateKeyMatchesCert(t *testing.T) {
	material := testfixtures.GenerateServerIdentityPEM(t)

	if err := ValidateKeyMatchesCert(material.ChainPem, material.PrivateKeyPem); err != nil {
		t.Fatalf("expected matching key/cert: %v", err)
	}
}

func TestValidateKeyMatchesCertMismatch(t *testing.T) {
	material := testfixtures.GenerateServerIdentityPEM(t)
	other := testfixtures.GenerateServerIdentityPEM(t)

	err := ValidateKeyMatchesCert(material.ChainPem, other.PrivateKeyPem)
	if err == nil {
		t.Fatal("expected key mismatch error")
	}

	var coded *CodedError
	if !errors.As(err, &coded) || coded.Code != "ERR_KEY_MISMATCH" {
		t.Fatalf("expected ERR_KEY_MISMATCH, got %v", err)
	}
}
