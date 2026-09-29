package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
)

// Separate from revoke-client so that a renewal URL can be withdrawn without
// taking the certificate in use. There is no deny-server because the API has
// none.
func denyClient(args []string) {
	fs := flag.NewFlagSet("deny-client", flag.ExitOnError)
	cn := fs.String("cn", "", "common name of the enrolment to cancel")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki deny-client -cn <CN>\n\n")
		fmt.Fprintf(os.Stderr, "Cancel the client enrolment URLs of a name that have not been used.\n")
		fmt.Fprintf(os.Stderr, "A certificate the name already has is left alone. To take that away\n")
		fmt.Fprintf(os.Stderr, "too, use revoke-client.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *cn == "" || fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	api, caid, _ := connect()
	ctx := context.Background()

	live, err := liveCerts(ctx, api, caid, clientKind, *cn)
	if err != nil {
		log.Fatal(err)
	}

	var pending []certEntry
	for _, c := range live {
		if c.IssueState == pendingState {
			pending = append(pending, c)
		}
	}
	if len(pending) == 0 {
		// The API refuses this too, but without saying what to do instead
		if len(live) > 0 {
			log.Fatalf("%s: no enrolment URL is waiting to be used, only an issued certificate (%s). Run\n"+
				"  sakura-pki revoke-client -cn %s", *cn, describe(live[0]), *cn)
		}
		log.Fatalf("%s: no enrolment URL is waiting to be used", *cn)
	}

	failed := false
	for _, c := range pending {
		if err := api.DenyClient(ctx, caid, c.ID); err != nil {
			log.Printf("%s: could not deny (%s): %v", *cn, describe(c), err)
			failed = true
			continue
		}
		fmt.Fprintf(os.Stderr, "denied: client %s %s\n", *cn, describe(c))
	}
	if failed {
		os.Exit(1)
	}
}
