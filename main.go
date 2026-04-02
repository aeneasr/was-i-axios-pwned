package main

import (
	"context"
	"os"

	"github.com/aeneasr/was-i-axios-pwned/internal/scanner"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(scanner.RunCLI(
		context.Background(),
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		scanner.WithBuildInfo(scanner.BuildInfo{
			Version: version,
			Commit:  commit,
			Date:    date,
		}),
	))
}
