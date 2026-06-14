package testfixtures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// IdentityPEMPair holds a matching cert chain and private key for installer tests.
type IdentityPEMPair struct {
	ChainPem      string
	PrivateKeyPem string
}

// GenerateServerIdentityPEM creates a self-signed cert and PKCS#8 private key PEM pair.
func GenerateServerIdentityPEM(t *testing.T) IdentityPEMPair {
	t.Helper()

	chainPem, privateKeyPem, err := ServerIdentityPEM()
	if err != nil {
		t.Fatalf("generate server identity pem: %v", err)
	}

	return IdentityPEMPair{
		ChainPem:      chainPem,
		PrivateKeyPem: privateKeyPem,
	}
}

// ServerIdentityPEM returns a matching cert chain and private key for tests.
func ServerIdentityPEM() (chainPem, privateKeyPem string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "server-identity.test.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"server-identity.test.local"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM), nil
}
