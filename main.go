// sakura-pki issues server and client certificates from SAKURA Cloud Managed PKI.
//
// It never generates or writes a private key. Server certificates are issued
// against a CSR made on the host that will hold the key. Client certificates are
// issued as an enrolment URL, and the key is generated in the user's browser.
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	args := os.Args[2:]
	switch os.Args[1] {
	case "server":
		server(args)
	case "client":
		client(args)
	case "list":
		list(args)
	case "revoke":
		revoke(args)
	case "deny":
		deny(args)
	case "version":
		printVersion()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: sakura-pki <command> [args]\n\n")
	fmt.Fprintf(os.Stderr, "  server  issue a server certificate for a CSR\n")
	fmt.Fprintf(os.Stderr, "  client  issue an enrolment URL for a client certificate\n")
	fmt.Fprintf(os.Stderr, "  list    list issued certificates\n")
	fmt.Fprintf(os.Stderr, "  revoke  revoke an issued certificate\n")
	fmt.Fprintf(os.Stderr, "  deny    cancel a client enrolment URL that was never used\n")
	fmt.Fprintf(os.Stderr, "  version print version and exit\n\n")
	fmt.Fprintf(os.Stderr, "Run <command> -h for its arguments.\n")
	fmt.Fprintf(os.Stderr, "Credentials come from the environment: an API key or a service principal.\n")
}
