package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// printJSON writes the result of a command to stdout.
//
// Data goes to stdout and everything else to stderr, so that redirecting stdout
// captures the result and nothing else. Errors, usage and confirmations are for
// a person to read, so they stay plain text.
func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, string(b))
}
