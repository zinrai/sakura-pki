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

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	ttl := fs.Duration("ttl", 8760*time.Hour, "certificate lifetime")
	force := fs.Bool("force", false, "issue even if a live certificate for this name exists")
	var sub subject
	sub.bind(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki client [flags] <CN>...\n\n")
		fmt.Fprintf(os.Stderr, "Issue an enrolment URL per user. The key is generated in the user's\n")
		fmt.Fprintf(os.Stderr, "browser and reaches neither this tool nor the CA.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}
	id, err := caID()
	if err != nil {
		log.Fatal(err)
	}

	api, err := newAPI()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	// Check every name first, so that a clash on the third name does not leave
	// the first two already issued
	if !*force {
		for _, cn := range fs.Args() {
			in, err := cnInUse(ctx, api, id, "clients", cn)
			if err != nil {
				log.Fatal(err)
			}
			if in != nil {
				log.Fatal(inUseError(cn, in))
			}
		}
	}

	issued, err := issueClients(ctx, api, id, notAfter(*ttl), sub, fs.Args())
	if err != nil {
		log.Fatal(err)
	}
	printJSON(issued)
}

// enrolment is what an operator hands to a user.
type enrolment struct {
	CN  string `json:"cn"`
	ID  string `json:"id"`
	URL string `json:"url"`
}

// issueClients has no csr or public_key path. Both would leave the private key
// with whoever generated it, which is what using a managed CA is meant to avoid.
// A machine that needs a client certificate cannot press a button in a browser,
// so a way to submit a CSR would have to be added when that case appears.
func issueClients(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID, na time.Time, sub subject, names []string) ([]enrolment, error) {
	out := []enrolment{}
	for _, cn := range names {
		added, err := api.AddClient(ctx, id, &iaas.CertificateAuthorityAddClientParam{
			Country:          sub.country,
			Organization:     sub.org,
			OrganizationUnit: sub.ou,
			CommonName:       cn,
			NotAfter:         na,
			IssuanceMethod:   issuanceURL,
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

		out = append(out, enrolment{CN: cn, ID: added.ID, URL: c.URL})
	}
	return out, nil
}
