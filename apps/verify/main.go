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
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/cmd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: depose-verify verify [options] <path-to-bundle>\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  --expected-key-fingerprint <hex>    Reject the bundle if the producer key fingerprint doesn't match.\n")
		fmt.Fprintf(os.Stderr, "  --revocation-list <path>            Reject if the producer key fingerprint is marked revoked in the catalog.\n")
		fmt.Fprintf(os.Stderr, "  --signer-identity <regex>           (Future) Sigstore signer identity binding.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  verify        Validate a .depo bundle.\n")
		fmt.Fprintf(os.Stderr, "  version       Print the verifier version.\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "verify":
		// flags: positional bundle path, plus optional pinning flags
		// for the air-gapped key-fingerprint discipline and the
		// (future) Sigstore signer-identity binding.
		var bundlePath string
		var expectedFingerprint string
		var signerIdentity string
		var revocationList string
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			switch {
			case arg == "--expected-key-fingerprint" && i+1 < len(os.Args):
				expectedFingerprint = os.Args[i+1]
				i++
			case strings.HasPrefix(arg, "--expected-key-fingerprint="):
				expectedFingerprint = strings.TrimPrefix(arg, "--expected-key-fingerprint=")
			case arg == "--revocation-list" && i+1 < len(os.Args):
				revocationList = os.Args[i+1]
				i++
			case strings.HasPrefix(arg, "--revocation-list="):
				revocationList = strings.TrimPrefix(arg, "--revocation-list=")
			case arg == "--signer-identity" && i+1 < len(os.Args):
				signerIdentity = os.Args[i+1]
				i++
			case strings.HasPrefix(arg, "--signer-identity="):
				signerIdentity = strings.TrimPrefix(arg, "--signer-identity=")
			case strings.HasPrefix(arg, "-"):
				fmt.Fprintf(os.Stderr, "ERROR: unknown flag %q\n", arg)
				os.Exit(1)
			default:
				if bundlePath != "" {
					fmt.Fprintf(os.Stderr, "ERROR: extra positional argument %q\n", arg)
					os.Exit(1)
				}
				bundlePath = arg
			}
		}
		if bundlePath == "" {
			fmt.Fprintf(os.Stderr, "ERROR: bundle path required\n")
			fmt.Fprintf(os.Stderr, "Usage: depose-verify verify [--expected-key-fingerprint <hex>] [--signer-identity <regex>] <path-to-bundle>\n")
			os.Exit(1)
		}
		absPath, err := filepath.Abs(bundlePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: invalid path %q: %v\n", bundlePath, err)
			os.Exit(1)
		}
		result := cmd.VerifyBundle(absPath, cmd.VerifyOpts{
			ExpectedKeyFingerprint: expectedFingerprint,
			SignerIdentityRegex:    signerIdentity,
			RevocationListPath:     revocationList,
		})
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