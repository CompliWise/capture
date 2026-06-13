package discovery

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

func parseCertificatePEM(data []byte) (*x509.Certificate, error) {
	var block *pem.Block
	rest := data
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate block found")
}

func thumbprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

func certToItem(
	cert *x509.Certificate,
	source, path, alias, trustStoreType string,
) DiscoveredItem {
	subjectCN := ""
	if cert.Subject.CommonName != "" {
		subjectCN = cert.Subject.CommonName
	}

	notAfter := ""
	if !cert.NotAfter.IsZero() {
		notAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	}

	return DiscoveredItem{
		Source:         source,
		Path:           path,
		Alias:          alias,
		Thumbprint:     thumbprintSHA256(cert),
		SubjectCN:      subjectCN,
		NotAfter:       notAfter,
		TrustStoreType: trustStoreType,
	}
}
