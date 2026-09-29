package main

import (
	"context"
	"crypto/x509"
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

func issueServer(args []string) {
	fs := flag.NewFlagSet("issue-server", flag.ExitOnError)
	csrPath := fs.String("csr", "", "CSR made on the host that will hold the key")
	cnFlag := fs.String("cn", "", "common name, taken from the CSR when not given")
	out := fs.String("out", "", "file to write the certificate to, <CN>.crt when not given")
	days := fs.Int("days", 365, "certificate lifetime in days")
	sans := fs.String("san", "", "comma separated subject alternative names, on top of the CN")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki issue-server -csr <FILE> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Issue a server certificate for a CSR. Make the CSR where the key will live:\n")
		fmt.Fprintf(os.Stderr, "  openssl req -new -newkey rsa:2048 -nodes \\\n")
		fmt.Fprintf(os.Stderr, "    -keyout proxy.key -out proxy.csr -subj /CN=proxy.example.internal\n\n")
		fmt.Fprintf(os.Stderr, "A name that already has a certificate stops this, unless it is about to\n")
		fmt.Fprintf(os.Stderr, "expire, in which case a new one is issued beside it. Running it again for\n")
		fmt.Fprintf(os.Stderr, "the same CSR writes out the certificate already issued for it.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *csrPath == "" || fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	req, err := prepareServer(*csrPath, *cnFlag, *sans, *out)
	if err != nil {
		log.Fatal(err)
	}

	api, caid, cert := connect()
	res, err := obtainServer(context.Background(), api, caid, subjectOf(cert), req, *days)
	if err != nil {
		log.Fatal(err)
	}

	written, err := writeServer(req.path, req.cn, res, req.csr, req.names)
	if err != nil {
		log.Fatal(err)
	}
	printJSON(written)
}

type serverRequest struct {
	csr    *x509.CertificateRequest
	csrPEM string
	cn     string
	names  []string
	path   string
}

// Worked out whole before the CA or the filesystem is touched, so that bad
// arguments leave nothing behind.
func prepareServer(csrPath, cn, sans, out string) (*serverRequest, error) {
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, err
	}
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	// Taken from the CSR rather than typed again, which would be a chance for the
	// two to disagree
	if cn == "" {
		cn = csr.Subject.CommonName
	}
	if cn == "" {
		return nil, errors.New("the CSR has no common name, so -cn is needed")
	}

	names, err := serverSANs(cn, splitSAN(sans))
	if err != nil {
		return nil, err
	}

	path := out
	if path == "" {
		path = cn + ".crt"
	}
	return &serverRequest{csr: csr, csrPEM: string(csrPEM), cn: cn, names: names, path: path}, nil
}

func obtainServer(ctx context.Context, api iaas.CertificateAuthorityAPI, caid iaasID, sub subject, req *serverRequest, days int) (*issueResult, error) {
	iss := newIssuer(api, caid)
	live, err := liveCerts(ctx, api, caid, serverKind, req.cn)
	if err != nil {
		return nil, err
	}
	now := time.Now()

	res, err := pickUp(ctx, iss.fetch, live, now, req.csr, req.names)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", req.cn, err)
	}
	if res != nil {
		fmt.Fprintf(os.Stderr, "%s: the certificate for this CSR was already issued, writing it out (id=%s)\n", req.cn, res.ID)
		return res, nil
	}

	if held := holding(live, now); len(held) > 0 {
		return nil, inUseError(req.cn, held[0])
	}
	for _, c := range live {
		fmt.Fprintf(os.Stderr, "%s: renewing, the current certificate is left to expire (%s)\n", req.cn, describe(c))
	}

	res, err = iss.Server(ctx, &iaas.CertificateAuthorityAddServerParam{
		Country:                   sub.country,
		Organization:              sub.org,
		CommonName:                req.cn,
		NotAfter:                  notAfter(days),
		SANs:                      req.names,
		CertificateSigningRequest: req.csrPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", req.cn, err)
	}
	return res, nil
}

// Stops, unlike issue-client: a server certificate is installed by hand, so a
// second one before the first is due is a mistake.
func inUseError(cn string, c certEntry) error {
	return fmt.Errorf("%s: a server certificate is in the way (%s). To replace it, run\n"+
		"  sakura-pki revoke-server -cn %s",
		cn, describe(c), cn)
}

// Without this, a run after a timeout is refused by the certificate the earlier
// run asked for. Matched by public key rather than name. Only certificates that
// hold the name count: a due one may share the key, and handing it back would
// undo the renewal.
func pickUp(ctx context.Context, fetch func(context.Context, string) (*issueResult, error), live []certEntry, now time.Time, csr *x509.CertificateRequest, sans []string) (*issueResult, error) {
	for _, c := range holding(live, now) {
		res, err := fetch(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		_, err = verifyServerCert(res.CertificatePEM, csr, sans)
		if errors.Is(err, errKeyMismatch) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w (id=%s)", err, c.ID)
		}
		return res, nil
	}
	return nil, nil
}

// Read back from the certificate rather than the request, so that what is
// printed is what the CA produced.
type issued struct {
	CN          string   `json:"cn"`
	ID          string   `json:"id"`
	Certificate string   `json:"certificate"`
	Subject     string   `json:"subject"`
	SANs        []string `json:"sans"`
	NotAfter    string   `json:"not_after"`
	Fingerprint string   `json:"fingerprint_sha256"`
}

// Verified before it is written, so that a wrong certificate never reaches the
// path the server loads.
func writeServer(path, cn string, res *issueResult, csr *x509.CertificateRequest, sans []string) (*issued, error) {
	cert, err := verifyServerCert(res.CertificatePEM, csr, sans)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (id=%s)", cn, err, res.ID)
	}

	if err := writePEM(path, pemOf(cert)); err != nil {
		return nil, fmt.Errorf("%s: %w", cn, err)
	}
	return &issued{
		CN:          cn,
		ID:          res.ID,
		Certificate: path,
		Subject:     cert.Subject.String(),
		SANs:        cert.DNSNames,
		NotAfter:    cert.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint: fingerprint(cert),
	}, nil
}

// The CN is added because current clients match only SANs. IP addresses are
// rejected because the API makes every entry a DNS name, which never matches
// a host reached by IP.
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
