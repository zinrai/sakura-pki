package main

import (
	"testing"
)

func TestPickCATakesOnlyTheCAWithTheFingerprint(t *testing.T) {
	ca := func(id int, name string) caEntry {
		pub, _ := key(t)
		cert, err := parseCert(certFor(t, pub, nil))
		if err != nil {
			t.Fatal(err)
		}
		return caEntry{id: iaasID(id), name: name, cert: cert}
	}
	staging, production := ca(1, "staging-ca"), ca(2, "production-ca")
	cas := []caEntry{staging, production}

	got, err := pickCA(cas, fingerprint(production.cert))
	if err != nil {
		t.Fatal(err)
	}
	if got.name != "production-ca" {
		t.Fatalf("picked %s, want production-ca", got.name)
	}

	other := ca(3, "elsewhere")
	if got, err := pickCA(cas, fingerprint(other.cert)); err == nil {
		t.Fatalf("picked %s for a fingerprint no CA here has", got.name)
	}
}
