// sakura-pki issues server and client certificates from SAKURA Cloud Managed PKI.
// It never generates or writes a private key.
package main

import (
	"fmt"
	"log"
	"os"
)

// The kind is part of the command name rather than a flag, so that each command
// has only the flags that apply to it.
const (
	clientKind = "client"
	serverKind = "server"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	args := os.Args[2:]
	switch os.Args[1] {
	case "list-ca":
		listCA(args)
	case "get-ca":
		getCA(args)
	case "issue-client":
		issueClient(args)
	case "issue-server":
		issueServer(args)
	case "revoke-client":
		revoke(clientKind, args)
	case "revoke-server":
		revoke(serverKind, args)
	case "deny-client":
		denyClient(args)
	case "list-client":
		list(clientKind, args)
	case "list-server":
		list(serverKind, args)
	case "version":
		printVersion()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: sakura-pki <command> [flags]\n\n")
	fmt.Fprintf(os.Stderr, "  list-ca        list the CAs in this account with their fingerprints\n")
	fmt.Fprintf(os.Stderr, "  get-ca         write the CA certificate to a file\n")
	fmt.Fprintf(os.Stderr, "  issue-client   issue an enrolment URL per user\n")
	fmt.Fprintf(os.Stderr, "  issue-server   issue a certificate for a CSR\n")
	fmt.Fprintf(os.Stderr, "  revoke-client  revoke a client certificate\n")
	fmt.Fprintf(os.Stderr, "  revoke-server  revoke a server certificate\n")
	fmt.Fprintf(os.Stderr, "  deny-client    cancel an enrolment URL that was never used\n")
	fmt.Fprintf(os.Stderr, "  list-client    list client certificates and enrolments\n")
	fmt.Fprintf(os.Stderr, "  list-server    list server certificates\n")
	fmt.Fprintf(os.Stderr, "  version        print version and exit\n\n")
	fmt.Fprintf(os.Stderr, "Run a command with -h for its flags.\n")
	fmt.Fprintf(os.Stderr, "Credentials come from the environment. An API key works, or a service principal.\n")
	fmt.Fprintf(os.Stderr, "The CA is the one whose certificate has the fingerprint in\n")
	fmt.Fprintf(os.Stderr, "SAKURA_PKI_CA_FINGERPRINT. list-ca shows them.\n")
}
