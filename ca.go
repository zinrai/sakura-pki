package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

// Issuing refuses a name that already has a live certificate, so folding this
// back into server or client would put the CA certificate out of reach once
// everything has been issued.
func ca(args []string) {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	out := fs.String("out", "./out", "output directory")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki ca [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Write the CA certificate. Nothing is issued.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 0 {
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

	path, err := writeCACert(context.Background(), api, id, *out)
	if err != nil {
		log.Fatal(err)
	}
	printJSON(struct {
		CACertificate string `json:"ca_certificate"`
	}{path})
}
