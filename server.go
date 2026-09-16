package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cnFlag := fs.String("cn", "", "common name of the certificate")
	csrPath := fs.String("csr", "", "CSR made on the host that will hold the key")
	out := fs.String("out", "./out", "output directory")
	ttl := fs.Duration("ttl", 8760*time.Hour, "certificate lifetime")
	sans := fs.String("san", "", "comma separated subject alternative names")
	force := fs.Bool("force", false, "issue even if a live certificate for this name exists")
	var sub subject
	sub.bind(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki server -cn <CN> -csr <FILE> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Issue a server certificate for a CSR. Make the CSR where the key will live:\n")
		fmt.Fprintf(os.Stderr, "  openssl req -new -newkey rsa:2048 -nodes \\\n")
		fmt.Fprintf(os.Stderr, "    -keyout proxy.key -out proxy.csr -subj /CN=<CN>\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *cnFlag == "" || *csrPath == "" || fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	id, err := caID()
	if err != nil {
		log.Fatal(err)
	}

	// Check the input before touching the CA or the filesystem, so that bad
	// arguments leave nothing behind to clean up
	cn := *cnFlag
	names, err := serverSANs(cn, splitSAN(*sans))
	if err != nil {
		log.Fatal(err)
	}

	csrPEM, err := os.ReadFile(*csrPath)
	if err != nil {
		log.Fatal(err)
	}

	api, err := newAPI()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if !*force {
		if in, err := cnInUse(ctx, api, id, "servers", cn); err != nil {
			log.Fatal(err)
		} else if in != nil {
			log.Fatal(inUseError(cn, in))
		}
	}

	res, err := issueServer(ctx, newIssuer(api, id), *out, notAfter(*ttl), sub,
		cn, names, string(csrPEM))
	if err != nil {
		log.Fatal(err)
	}
	printJSON(res)
}

// issued is what the caller needs after a server certificate is written.
type issued struct {
	CN          string `json:"cn"`
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
}

// issueServer writes the certificate last so that a failure part way through
// does not replace a working certificate with an empty file.
func issueServer(ctx context.Context, iss *issuer, out string, na time.Time, sub subject, cn string, sans []string, csrPEM string) (*issued, error) {
	res, err := iss.Server(ctx, &iaas.CertificateAuthorityAddServerParam{
		Country:                   sub.country,
		Organization:              sub.org,
		OrganizationUnit:          sub.ou,
		CommonName:                cn,
		NotAfter:                  na,
		SANs:                      sans,
		CertificateSigningRequest: csrPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cn, err)
	}

	path, err := writeCert(out, "server", cn, res.CertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cn, err)
	}
	return &issued{
		CN:          cn,
		ID:          res.ID,
		Certificate: path,
	}, nil
}

// serverSANs adds the CN because implementations other than the ones that still
// read the CN will not match a name that is absent from the SANs.
//
// It rejects IP addresses. This CA puts every SANs entry in as a DNS name, so an
// IP becomes DNS:127.0.0.1, and TLS only matches an iPAddress SAN when the peer
// is reached by IP. The API has no way to ask for an iPAddress SAN, so letting
// one through would only produce a certificate that cannot be used and has to be
// revoked.
func serverSANs(cn string, sans []string) ([]string, error) {
	if !contains(sans, cn) {
		sans = append([]string{cn}, sans...)
	}

	// Report every offending entry rather than stopping at the first one
	var ips []string
	for _, n := range sans {
		if net.ParseIP(n) != nil {
			ips = append(ips, n)
		}
	}
	if len(ips) > 0 {
		return nil, fmt.Errorf("%w: %s", errIPSAN, strings.Join(ips, ", "))
	}
	return sans, nil
}

func splitSAN(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

var errIPSAN = errors.New("an IP address cannot be used as a SAN")
