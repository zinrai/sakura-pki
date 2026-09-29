package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// Results go to stdout and everything else to stderr, so that redirecting stdout
// captures only the result.
func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, string(b))
}
