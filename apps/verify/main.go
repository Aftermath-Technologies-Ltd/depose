// Package main — depose-verify: standalone verifier for .depo evidence bundles.
//
// Reads a .depo bundle directory and validates:
//   1. Manifest signature (Ed25519)
//   2. Hash chain integrity (IRONROOT replay)
//   3. Artifact SHA-256 hashes
//   4. RFC 3161 timestamp validity
//
// Pure stdlib + minimal deps. No network required for core verification.
// Rekor verification is optional and skipped gracefully if unavailable.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/cmd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: depose-verify verify <path-to-bundle>\n")
		fmt.Fprintf(os.Stderr, "       depose-verify version\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "verify":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "ERROR: bundle path required\n")
			fmt.Fprintf(os.Stderr, "Usage: depose-verify verify <path-to-bundle>\n")
			os.Exit(1)
		}
		bundlePath := os.Args[2]
		absPath, err := filepath.Abs(bundlePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid path %q: %v\n", bundlePath, err)
			os.Exit(1)
		}
		result := cmd.VerifyBundle(absPath)
		result.Print()
		if !result.Pass {
			os.Exit(1)
		}

	case "version":
		fmt.Println("depose-verify 0.1.0")

	default:
		fmt.Fprintf(os.Stderr, "ERROR: unknown command %q\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "Commands: verify, version\n")
		os.Exit(1)
	}
}