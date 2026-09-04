package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

func list(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki list\n\n")
		fmt.Fprintf(os.Stderr, "Print issued certificates as JSON. Revocation takes the ids.\n")
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
	ctx := context.Background()

	// One array rather than one per kind, so that a filter over everything is a
	// single jq expression
	all := []certEntry{}
	for _, kind := range []string{"clients", "servers"} {
		certs, err := listCerts(ctx, api, id, kind)
		if err != nil {
			log.Fatal(err)
		}
		all = append(all, certs...)
	}

	printJSON(all)
}

func revoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	client := fs.String("client", "", "client certificate id to revoke")
	server := fs.String("server", "", "server certificate id to revoke")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki revoke (-client <ID> | -server <ID>)\n\n")
		fmt.Fprintf(os.Stderr, "Revoke a certificate. This cannot be undone. Ids come from list.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	// Accepting both would leave no record of which one was revoked
	if (*client == "") == (*server == "") {
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

	if *client != "" {
		if err := api.RevokeClient(ctx, id, *client); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(os.Stderr, "revoked: client %s\n", *client)
		return
	}

	if err := api.RevokeServer(ctx, id, *server); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "revoked: server %s\n", *server)
}

// deny cancels a pending enrolment. It is not part of revoke because the two are
// different operations on the CA and leave different states behind, and because
// the API has no equivalent for server certificates.
func deny(args []string) {
	fs := flag.NewFlagSet("deny", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki deny <ID>\n\n")
		fmt.Fprintf(os.Stderr, "Cancel a client enrolment URL that has not been used. An issued\n")
		fmt.Fprintf(os.Stderr, "certificate cannot be cancelled this way; revoke it instead.\n")
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
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

	if err := api.DenyClient(context.Background(), id, fs.Arg(0)); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "denied: client %s\n", fs.Arg(0))
}
