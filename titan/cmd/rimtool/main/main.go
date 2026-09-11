// Package main implements the entry point module for the rimtool CLI binary.
package main

import (
	"os"

	"github.com/google/platform-attestation/titan/cmd/rimtool"
)

func main() {
	if err := rimtool.RunApp(os.Args, os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}
