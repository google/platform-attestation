// Package rimtool implements the business logic for the rimtool platform attestation CLI utility.
package rimtool

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/platform-attestation/titan/bundlev2"
	"github.com/google/platform-attestation/titan/descriptor"
	"github.com/google/platform-attestation/titan/titanheader"
)

type firmwareType string

const (
	titanV2         firmwareType = "titan_v2"
	imageDescriptor firmwareType = "image_descriptor"
)

// RunApp parses parameters, sniffs target firmware types, and executes platform attestation hash checks.
func RunApp(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		printUsage(stderr)
		return fmt.Errorf("missing subcommand")
	}

	subcommand := args[1]
	switch subcommand {
	case "generate-hash":
		return runGenerateHash(args[2:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Error: Unknown command %q\n\n", subcommand)
		printUsage(stderr)
		return fmt.Errorf("unknown command %s", subcommand)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: rimtool <command> [flags]")
	fmt.Fprintln(w, "\nAvailable Commands:")
	fmt.Fprintln(w, "  generate-hash   Generate attestation hashes for firmware packages")
	fmt.Fprintln(w, "\nUse \"rimtool <command> --help\" for more information about a command.")
}

func runGenerateHash(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("generate-hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pathFlag := fs.String("path", "", "Path to the target firmware binary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *pathFlag == "" {
		fmt.Fprintln(stderr, "Error: the --path flag is required.")
		fs.Usage()
		return fmt.Errorf("missing --path flag")
	}

	f, err := os.Open(*pathFlag)
	if err != nil {
		return fmt.Errorf("failed to open target file %q: %w", *pathFlag, err)
	}
	defer f.Close()

	// 1. Sniff Step A: Check if it is a Titan V2 Bundle.
	if _, err := titanheader.ScanHeader(f); err == nil {
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			res, err := bundlev2.HashBundleV2(f)
			if err == nil {
				majorStr := fmt.Sprintf("%d", res.Major)
				printCLIResult(titanV2, "", majorStr, res.Digest, stdout)
				return nil
			}
		}
	}

	// 2. Sniff Step B: Check if it is a BIOS/BMC Image Descriptor.
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		descHash, err := descriptor.ExtractAndHash(f)
		if err == nil {
			hashName := descriptor.HashTypeName[descHash.HashType()]
			printCLIResult(imageDescriptor, hashName, "", descHash.Digest(), stdout)
			return nil
		}
	}

	// 3. Fallback: Binary packaging not recognized.
	return fmt.Errorf("unrecognized or corrupt firmware packaging format (failed both Titan V2 and BIOS/BMC audits)")
}

func printCLIResult(typ firmwareType, hashType, payloadVersion string, digest []byte, w io.Writer) {
	digestHex := hex.EncodeToString(digest)

	if typ == titanV2 {
		fmt.Fprintln(w, "Type:    Titan V2 Bundle")
		fmt.Fprintf(w, "Version: %s\n", payloadVersion)
	} else {
		fmt.Fprintln(w, "Type:    Image Descriptor")
		fmt.Fprintf(w, "Hash:    %s\n", hashType)
	}
	fmt.Fprintf(w, "Digest:  %s\n", digestHex)
}
