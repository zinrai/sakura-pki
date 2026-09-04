package main

import "fmt"

// Overwritten by goreleaser via -ldflags -X, so the defaults are what a
// locally built binary reports
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	fmt.Printf("sakura-pki version %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", date)
}
