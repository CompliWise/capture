package probe

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestValidatePeerCertificatesUntrusted(t *testing.T) {
	cert := selfSignedTestCertificate(t)
	outcome := ValidatePeerCertificates([]*x509.Certificate{cert}, "selfsigned.example", false)
	if outcome.Result != validationUntrusted {
		t.Fatalf("expected untrusted, got %q", outcome.Result)
	}
}

func TestValidatePeerCertificatesOKInsecure(t *testing.T) {
	cert := selfSignedTestCertificate(t)
	outcome := ValidatePeerCertificates([]*x509.Certificate{cert}, "selfsigned.example", true)
	if outcome.Result != validationOK {
		t.Fatalf("expected ok, got %q (%v)", outcome.Result, outcome.Errors)
	}
}

func TestValidateHandshakeUsesPeerCerts(t *testing.T) {
	cert := selfSignedTestCertificate(t)
	result := HandshakeResult{
		PeerCerts:   []*x509.Certificate{cert},
		ChainSHA256: []string{"a"},
		ServerName:  "selfsigned.example",
	}
	outcome := ValidateHandshake(result, "selfsigned.example", true)
	if outcome.Result != validationOK {
		t.Fatalf("expected ok, got %q", outcome.Result)
	}
}

func TestPlaceholderChainSHA256IsStable(t *testing.T) {
	target := ProbeTarget{Host: "example.com", Port: 443, ServerName: "example.com"}
	first := PlaceholderChainSHA256(target)
	second := PlaceholderChainSHA256(target)
	if first != second || len(first) != 64 {
		t.Fatalf("unexpected placeholder: %q", first)
	}
}

func selfSignedTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "selfsigned.example",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		DNSNames:  []string{"selfsigned.example"},
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}
