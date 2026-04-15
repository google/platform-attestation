// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
)

// usage prints the general usage.
func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <subcommand> [arguments]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  verify    Verify a Titan certificate chain")
	fmt.Fprintln(os.Stderr, "  parse     Parse a Titan certificate chain (not yet implemented)")
	fmt.Fprintln(os.Stderr, "\nUse \"<subcommand> --help\" for more information about a subcommand.")
}

// verifyFlags holds the flags for the verify subcommand.
type verifyFlags struct {
	certChainPath string
}

// runVerify parses flags and executes the verify logic.
func runVerify(args []string) error {
	vf := &verifyFlags{}
	verifyCmd := flag.NewFlagSet("verify", flag.ContinueOnError)
	verifyCmd.StringVar(&vf.certChainPath, "cert_chain_path", "", "Path to the certificate chain file")

	if err := verifyCmd.Parse(args); err != nil {
		return err // Error on parsing will print usage from FlagSet.
	}

	// Validate flags
	if vf.certChainPath == "" {
		verifyCmd.Usage()
		return fmt.Errorf("--cert_chain_path is required")
	}
	return verifyCertChainFromFile(vf.certChainPath)
}

// runParse is a placeholder for the parse subcommand.
func runParse(args []string) error {
	parseCmd := flag.NewFlagSet("parse", flag.ContinueOnError)
	// TODO: Add flags for parse command

	if err := parseCmd.Parse(args); err != nil {
		return err
	}
	fmt.Println("Simulating parse command - not yet implemented.")
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	otherArgs := os.Args[2:]

	var err error
	switch subcommand {
	case "verify":
		err = runVerify(otherArgs)
	case "parse":
		err = runParse(otherArgs)
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown subcommand %q\n", subcommand)
		usage()
		os.Exit(1)
	}

	if err != nil {
		// flag.ContinueOnError means flag parsing errors don't exit, so we catch them here.
		if err == flag.ErrHelp {
			// Already handled by FlagSet, but being explicit.
			return
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
