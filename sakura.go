package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
	"github.com/sacloud/sacloud-sdk-go/api/iaas/types"
	"github.com/sacloud/sacloud-sdk-go/common/saclient"
)

// newAPI leaves credential resolution to saclient rather than reading the
// environment here, so that API keys and service principals keep being told
// apart the way the SDK documents.
//
// Managed PKI is zone independent and the SDK fills the default zone into the
// URL, so there is no zone to pass.
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
	ou      stringList
}

func (s *subject) bind(fs *flag.FlagSet) {
	fs.StringVar(&s.country, "country", "", "Country")
	fs.StringVar(&s.org, "org", "", "Organization")
	fs.Var(&s.ou, "ou", "Organizational Unit (repeatable)")
}

type stringList []string

func (l *stringList) String() string { return fmt.Sprint(*l) }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// caIDEnv holds the CA id next to the credentials it belongs to. A CA id only
// means anything against the account that owns it, so keeping the two in the
// same place removes the chance of pairing one environment's credentials with
// another environment's CA.
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

func notAfter(ttl time.Duration) time.Time {
	return time.Now().Add(ttl)
}
