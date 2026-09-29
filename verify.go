package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

var (
	errKeyMismatch = errors.New("the certificate holds a different public key from the CSR")
	errMissingSAN  = errors.New("the certificate is missing names that were asked for")
)

// Compared here rather than by eye: a wrong key fails every handshake and a
// missing name fails on whoever connects, both long after deployment.
func verifyServerCert(certPEM string, csr *x509.CertificateRequest, sans []string) (*x509.Certificate, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}

	certKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not read the public key of the certificate: %w", err)
	}
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not read the public key of the CSR: %w", err)
	}
	if !bytes.Equal(certKey, csrKey) {
		return nil, errKeyMismatch
	}

	var missing []string
	for _, n := range sans {
		if !contains(cert.DNSNames, n) {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s (it has %s)", errMissingSAN,
			strings.Join(missing, ", "), strings.Join(cert.DNSNames, ", "))
	}
	return cert, nil
}

func parseCert(certPEM string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("the CA did not return a PEM certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not read the certificate: %w", err)
	}
	return cert, nil
}

// Before issuing, since a CSR the CA accepts but this tool cannot read leaves a
// certificate to revoke.
func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("the CSR is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not read the CSR: %w", err)
	}
	return csr, nil
}

// Re-encoded from what was parsed, so that the file holds the bytes the
// fingerprint was taken over.
func pemOf(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// Spelled as openssl spells it, so that it compares directly with a deployed
// certificate.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
