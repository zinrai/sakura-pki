package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

func waiter() *issuer {
	return &issuer{interval: time.Millisecond, timeout: 200 * time.Millisecond}
}

// Giving up after one read treats a finished issuance as a failure.
func TestWaitKeepsReadingUntilTheCertificateAppears(t *testing.T) {
	reads := 0
	read := func(context.Context) (string, *iaas.CertificateData, error) {
		reads++
		if reads < 3 {
			return "pending", nil, nil
		}
		return "available", &iaas.CertificateData{CertificatePEM: "pem"}, nil
	}

	res, err := waiter().wait(context.Background(), "cert-1", read)
	if err != nil {
		t.Fatal(err)
	}
	if res.CertificatePEM != "pem" {
		t.Errorf("the certificate was not returned: %q", res.CertificatePEM)
	}
	if reads != 3 {
		t.Errorf("want 3 reads, got %d", reads)
	}
}

// Reporting success with nothing in hand writes an empty certificate.
func TestWaitFailsWhenTheCertificateNeverAppears(t *testing.T) {
	read := func(context.Context) (string, *iaas.CertificateData, error) {
		return "pending", nil, nil
	}

	_, err := waiter().wait(context.Background(), "cert-1", read)
	if !errors.Is(err, errTimeout) {
		t.Fatalf("want errTimeout, got %v", err)
	}
}

// Matching on a state name fails an issued certificate whenever a value we did
// not anticipate comes back.
func TestWaitJudgesByTheCertificateNotTheState(t *testing.T) {
	read := func(context.Context) (string, *iaas.CertificateData, error) {
		return "a state this API may or may not return", &iaas.CertificateData{CertificatePEM: "pem"}, nil
	}

	if _, err := waiter().wait(context.Background(), "cert-1", read); err != nil {
		t.Fatalf("the certificate was there but it failed: %v", err)
	}
}
