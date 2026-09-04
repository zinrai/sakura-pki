package main

import (
	"errors"
	"strings"
	"testing"
)

// Without the CN in the SANs, the certificate does not verify for its own name.
func TestServerSANsIncludeTheCN(t *testing.T) {
	got, err := serverSANs("proxy.example.internal", []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}

	if !contains(got, "proxy.example.internal") {
		t.Errorf("the CN is missing: %v", got)
	}
	if !contains(got, "localhost") {
		t.Errorf("a given SAN was dropped: %v", got)
	}
}

// Letting one through produces a certificate that fails only when the peer is
// reached by IP, and it has to be revoked.
func TestServerSANsRefuseIPs(t *testing.T) {
	_, err := serverSANs("a.example", []string{"10.0.0.1", "b.example", "::1"})

	if !errors.Is(err, errIPSAN) {
		t.Fatalf("want errIPSAN, got %v", err)
	}
	if !strings.Contains(err.Error(), "10.0.0.1") || !strings.Contains(err.Error(), "::1") {
		t.Errorf("every offending address should be reported, got %q", err)
	}
}
