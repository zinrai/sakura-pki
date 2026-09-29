package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
	"github.com/sacloud/sacloud-sdk-go/api/iaas/types"
	"github.com/sacloud/sacloud-sdk-go/common/saclient"
)

// The CA is printed on stderr because an environment variable picks it and
// nothing on stdout names it.
func connect() (iaas.CertificateAuthorityAPI, iaasID, *x509.Certificate) {
	id, err := caID()
	if err != nil {
		log.Fatal(err)
	}
	api, err := newAPI()
	if err != nil {
		log.Fatal(err)
	}
	cert, err := caCert(context.Background(), api, id)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, "CA: %s (id=%s)\n", cert.Subject.CommonName, id)
	return api, id, cert
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

// In the environment next to the credentials rather than in a flag, so that one
// environment's credentials are not paired with another's CA.
const caIDEnv = "SAKURA_PKI_CA_ID"

func caID() (types.ID, error) {
	v := os.Getenv(caIDEnv)
	if v == "" {
		return 0, fmt.Errorf("%s is not set", caIDEnv)
	}
	id := types.StringID(v)
	if id.IsEmpty() {
		return 0, fmt.Errorf("%s is not a valid CA id: %q", caIDEnv, v)
	}
	return id, nil
}

func notAfter(days int) time.Time {
	return time.Now().AddDate(0, 0, days)
}
