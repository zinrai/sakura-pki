package main

import (
	"context"
	"testing"
	"time"
)

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

func TestPickUpTakesOnlyAHeldCertificateOverTheSameKey(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pub, priv := key(t)
	csr := csrFor(t, priv)
	names := []string{"proxy.example.internal"}
	pem := certFor(t, pub, names)

	fetch := func(_ context.Context, id string) (*issueResult, error) {
		return &issueResult{ID: id, CertificatePEM: pem}, nil
	}
	cert := func(id string, notAfter time.Time) certEntry {
		return certEntry{ID: id, IssueState: "available", notBefore: notAfter.AddDate(-1, 0, 0), notAfter: notAfter}
	}

	due := cert("due", now.AddDate(0, 0, 10))
	res, err := pickUp(context.Background(), fetch, []certEntry{due}, now, csr, names)
	if err != nil {
		t.Fatal(err)
	}
	if res != nil {
		t.Fatalf("picked up %s, which is due for renewal", res.ID)
	}

	held := cert("held", now.AddDate(0, 6, 0))
	res, err = pickUp(context.Background(), fetch, []certEntry{due, held}, now, csr, names)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.ID != "held" {
		t.Fatalf("want held picked up, got %+v", res)
	}
}
