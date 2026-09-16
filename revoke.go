package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

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
