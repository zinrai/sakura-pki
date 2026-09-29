package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

// The kind is in the command name so that an irreversible command always says
// what it acts on.
//
// Every live certificate of the name rather than one: there are two only during
// renewal, and both are in the same hands. Unused enrolment URLs are cancelled
// too, or one could be used to come back.
func revoke(kind string, args []string) {
	fs := flag.NewFlagSet("revoke-"+kind, flag.ExitOnError)
	cn := fs.String("cn", "", "common name of the certificate to revoke")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki revoke-%s -cn <CN>\n\n", kind)
		fmt.Fprintf(os.Stderr, "Revoke every live %s certificate with this name. This cannot be undone.\n", kind)
		if kind == clientKind {
			fmt.Fprintf(os.Stderr, "Enrolment URLs for the name that have not been used are cancelled too.\n")
		}
		fmt.Fprintf(os.Stderr, "\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *cn == "" || fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	api, caid, _ := connect()
	ctx := context.Background()

	live, err := liveCerts(ctx, api, caid, kind, *cn)
	if err != nil {
		log.Fatal(err)
	}
	if len(live) == 0 {
		log.Fatalf("%s: no live %s certificate has this name", *cn, kind)
	}

	// Carry on past a failure so that one refusal does not leave the rest in place
	failed := false
	for _, c := range live {
		done, err := revokeOne(ctx, api, caid, kind, c)
		if err != nil {
			log.Printf("%s: could not revoke (%s): %v", *cn, describe(c), err)
			failed = true
			continue
		}
		fmt.Fprintf(os.Stderr, "%s: %s %s %s\n", done, kind, *cn, describe(c))
	}
	if failed {
		os.Exit(1)
	}
}

func revokeOne(ctx context.Context, api iaas.CertificateAuthorityAPI, caid iaasID, kind string, c certEntry) (string, error) {
	switch {
	case kind == clientKind && c.IssueState == pendingState:
		return "denied", api.DenyClient(ctx, caid, c.ID)
	case kind == clientKind:
		return "revoked", api.RevokeClient(ctx, caid, c.ID)
	default:
		return "revoked", api.RevokeServer(ctx, caid, c.ID)
	}
}
