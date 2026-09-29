package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func key(t *testing.T) (crypto.PublicKey, crypto.Signer) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func csrFor(t *testing.T, priv crypto.Signer) *x509.CertificateRequest {
	t.Helper()

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "proxy.example.internal"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// certFor stands in for what the CA sends back, a certificate over some public
// key, carrying some names.
func certFor(t *testing.T, pub crypto.PublicKey, dns []string) string {
	t.Helper()

	_, signer := key(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy.example.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestVerifyRejectsACertificateForAnotherKey(t *testing.T) {
	_, mine := key(t)
	theirs, _ := key(t)

	_, err := verifyServerCert(certFor(t, theirs, []string{"proxy.example.internal"}),
		csrFor(t, mine), []string{"proxy.example.internal"})

	if !errors.Is(err, errKeyMismatch) {
		t.Fatalf("want errKeyMismatch, got %v", err)
	}
}

func TestVerifyAcceptsTheCertificateThatWasAskedFor(t *testing.T) {
	pub, priv := key(t)
	names := []string{"proxy.example.internal", "localhost"}

	if _, err := verifyServerCert(certFor(t, pub, names), csrFor(t, priv), names); err != nil {
		t.Fatal(err)
	}
}
