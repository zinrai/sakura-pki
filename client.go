package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

func issueClient(args []string) {
	fs := flag.NewFlagSet("issue-client", flag.ExitOnError)
	cnFlag := fs.String("cn", "", "common name of the certificate")
	days := fs.Int("days", 365, "certificate lifetime in days")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki issue-client -cn <CN> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Issue an enrolment URL for one user. The key is generated in their\n")
		fmt.Fprintf(os.Stderr, "browser and reaches neither this tool nor the CA.\n\n")
		fmt.Fprintf(os.Stderr, "A name that already has a certificate is reported and left alone, unless\n")
		fmt.Fprintf(os.Stderr, "it is about to expire, in which case a new one is issued beside it. So this\n")
		fmt.Fprintf(os.Stderr, "can be run over a list of people as often as the list changes, and it\n")
		fmt.Fprintf(os.Stderr, "renews as it goes. To replace a certificate that is not about to expire,\n")
		fmt.Fprintf(os.Stderr, "revoke-client it first.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *cnFlag == "" || fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	cn := *cnFlag

	api, caid, cert := connect()
	ctx := context.Background()

	live, err := liveCerts(ctx, api, caid, clientKind, cn)
	if err != nil {
		log.Fatal(err)
	}
	// Reported rather than failed, since a roster run meets this for almost
	// everyone, and kept off stdout so a run captures only the URLs
	if held := holding(live, time.Now()); len(held) > 0 {
		if held[0].IssueState == pendingState {
			fmt.Fprintf(os.Stderr, "%s: an enrolment URL is waiting to be used (%s)\n", cn, describe(held[0]))
		} else {
			fmt.Fprintf(os.Stderr, "%s: already has a client certificate (%s)\n", cn, describe(held[0]))
		}
		return
	}
	for _, c := range live {
		fmt.Fprintf(os.Stderr, "%s: renewing, the current certificate is left to expire (%s)\n", cn, describe(c))
	}

	issued, err := requestClient(ctx, api, caid, notAfter(*days), subjectOf(cert), cn)
	if err != nil {
		log.Fatal(err)
	}
	printJSON(issued)
}

type enrolment struct {
	CN  string `json:"cn"`
	ID  string `json:"id"`
	URL string `json:"url"`
}

// Only the URL method: csr and public_key would leave the private key with
// whoever made it. A machine that needs a client certificate will need a CSR
// path added.
func requestClient(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID, na time.Time, sub subject, cn string) (*enrolment, error) {
	added, err := api.AddClient(ctx, id, &iaas.CertificateAuthorityAddClientParam{
		Country:        sub.country,
		Organization:   sub.org,
		CommonName:     cn,
		NotAfter:       na,
		IssuanceMethod: issuanceURL,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: could not request issuance: %w", cn, err)
	}

	// AddClient returns only an id, so the URL comes from ReadClient
	c, err := api.ReadClient(ctx, id, added.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: could not read the enrolment URL: %w", cn, err)
	}
	if c.URL == "" {
		return nil, fmt.Errorf("%s: the enrolment URL was empty (IssueState=%q)", cn, c.IssueState)
	}

	return &enrolment{CN: cn, ID: added.ID, URL: c.URL}, nil
}
