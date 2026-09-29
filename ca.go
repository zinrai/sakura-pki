package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

// Not part of issue-server, which refuses a name already taken and so would put
// the CA certificate out of reach once everything has been issued.
func exportCA(args []string) {
	fs := flag.NewFlagSet("export-ca", flag.ExitOnError)
	out := fs.String("out", "ca.crt", "file to write the CA certificate to")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki export-ca [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Write the CA certificate. Nothing is issued.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	_, _, cert := connect()
	if err := writePEM(*out, pemOf(cert)); err != nil {
		log.Fatal(err)
	}

	// The fingerprint lets a host check that the ca.crt it holds is this CA's
	printJSON(struct {
		CACertificate string `json:"ca_certificate"`
		Subject       string `json:"subject"`
		NotAfter      string `json:"not_after"`
		Fingerprint   string `json:"fingerprint_sha256"`
	}{
		CACertificate: *out,
		Subject:       cert.Subject.String(),
		NotAfter:      cert.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint:   fingerprint(cert),
	})
}

func listCA(args []string) {
	fs := flag.NewFlagSet("list-ca", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki list-ca\n\n")
		fmt.Fprintf(os.Stderr, "Print the CAs in this account as JSON, with the fingerprint that\n")
		fmt.Fprintf(os.Stderr, "%s takes.\n", caFingerprintEnv)
	}
	fs.Parse(args)

	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	api, err := newAPI()
	if err != nil {
		log.Fatal(err)
	}
	cas, err := listCAs(context.Background(), api)
	if err != nil {
		log.Fatal(err)
	}

	out := make([]listedCA, 0, len(cas))
	for _, c := range cas {
		out = append(out, listedCAOf(c))
	}
	printJSON(out)
}

type listedCA struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
	Fingerprint string `json:"fingerprint_sha256"`
}

func listedCAOf(c caEntry) listedCA {
	return listedCA{
		ID:          c.id.String(),
		Name:        c.name,
		Subject:     c.cert.Subject.String(),
		NotAfter:    c.cert.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint: fingerprint(c.cert),
	}
}
