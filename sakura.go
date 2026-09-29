package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
	"github.com/sacloud/sacloud-sdk-go/common/saclient"
)

// By fingerprint rather than id: a wrong id works on another CA without a word,
// while a wrong fingerprint matches nothing and stops.
const caFingerprintEnv = "SAKURA_PKI_CA_FINGERPRINT"

// The CA's name is printed as well as its common name, since two CAs in one
// account can share a common name.
func connect() (iaas.CertificateAuthorityAPI, iaasID, *x509.Certificate) {
	want := os.Getenv(caFingerprintEnv)
	if want == "" {
		log.Fatalf("%s is not set. Run sakura-pki list-ca to find it", caFingerprintEnv)
	}
	api, err := newAPI()
	if err != nil {
		log.Fatal(err)
	}
	cas, err := listCAs(context.Background(), api)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := pickCA(cas, want)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, "CA: %s (%s, id=%s)\n", ca.name, ca.cert.Subject.CommonName, ca.id)
	return api, ca.id, ca.cert
}

type caEntry struct {
	id   iaasID
	name string
	cert *x509.Certificate
}

func listCAs(ctx context.Context, api iaas.CertificateAuthorityAPI) ([]caEntry, error) {
	found, err := pageThrough(func(from int) ([]*iaas.CertificateAuthority, int, error) {
		res, err := api.Find(ctx, &iaas.FindCondition{From: from, Count: pageSize})
		if err != nil {
			return nil, 0, fmt.Errorf("could not list the CAs: %w", err)
		}
		return res.CertificateAuthorities, res.Total, nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]caEntry, 0, len(found))
	for _, c := range found {
		cert, err := caCert(ctx, api, c.ID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		out = append(out, caEntry{id: c.ID, name: c.Name, cert: cert})
	}
	return out, nil
}

func pickCA(cas []caEntry, want string) (*caEntry, error) {
	for i, c := range cas {
		if fingerprint(c.cert) == want {
			return &cas[i], nil
		}
	}
	return nil, fmt.Errorf("no CA in this account has the fingerprint in %s. Run\n"+
		"  sakura-pki list-ca\nto see the ones there are", caFingerprintEnv)
}

// Credentials are left to saclient rather than read here, so that API keys and
// service principals are told apart as the SDK documents. No zone is passed
// because Managed PKI is global.
func newAPI() (iaas.CertificateAuthorityAPI, error) {
	var sc saclient.Client
	if err := sc.SetEnviron(os.Environ()); err != nil {
		return nil, fmt.Errorf("could not read credentials: %w", err)
	}
	if err := sc.Populate(); err != nil {
		return nil, fmt.Errorf("could not read credentials: %w", err)
	}
	return iaas.NewCertificateAuthorityOp(iaas.NewClientFromSaclient(&sc)), nil
}

type subject struct {
	country string
	org     string
}

// Not a flag: this CA serves one installation, so what it issues shares its
// organisation, and a flag would only let one certificate silently disagree.
// The CA's organisational unit is not the holder's, so it is left out.
func subjectOf(cert *x509.Certificate) subject {
	var s subject
	if len(cert.Subject.Country) > 0 {
		s.country = cert.Subject.Country[0]
	}
	if len(cert.Subject.Organization) > 0 {
		s.org = cert.Subject.Organization[0]
	}
	return s
}

func notAfter(days int) time.Time {
	return time.Now().AddDate(0, 0, days)
}
