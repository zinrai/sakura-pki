package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

// deny cancels a pending enrolment. It is not part of revoke because the two are
// different operations on the CA and leave different states behind, and because
// the API has no equivalent for server certificates.
func deny(args []string) {
	fs := flag.NewFlagSet("deny", flag.ExitOnError)
	client := fs.String("client", "", "client enrolment id to cancel")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki deny -client <ID>\n\n")
		fmt.Fprintf(os.Stderr, "Cancel a client enrolment URL that has not been used. An issued\n")
		fmt.Fprintf(os.Stderr, "certificate cannot be cancelled this way; revoke it instead.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *client == "" || fs.NArg() != 0 {
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

	if err := api.DenyClient(context.Background(), id, *client); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "denied: client %s\n", *client)
}
