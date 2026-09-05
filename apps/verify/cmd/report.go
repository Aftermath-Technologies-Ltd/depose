// Package cmd, human-readable and JSON rendering of a verification result.
package cmd

import (
	"encoding/json"
	"fmt"
)

func (r *VerifyResult) Print() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║            DEPOSE Evidence Bundle Verification Report          ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Bundle: %s\n", r.Bundle)
	fmt.Printf("  Mode:   %s\n", r.Mode)
	if r.Disclosure {
		fmt.Printf("  Kind:   disclosure (%d of %d sealed events disclosed)\n", r.DisclosedEvents, r.LeafCount)
	}
	fmt.Println()

	if r.Mode == "dev-unsigned" {
		fmt.Println("  ⚠ THIS IS A DEVELOPMENT BUNDLE, NOT EVIDENCE")
		fmt.Println("    No signature, no timestamp. Suitable for pipeline testing only.")
		fmt.Println()
	}

	allPass := true
	for _, check := range r.Checks {
		icon := "✓"
		switch check.Status {
		case StatusFail:
			icon = "✗"
			allPass = false
		case StatusSkipped:
			icon = "-"
		case StatusWarn:
			icon = "!"
		}
		fmt.Printf("  [%s] %s: %s\n", icon, check.Name, check.Status)
		fmt.Printf("         %s\n", check.Detail)
	}

	fmt.Println()
	if allPass {
		if r.Mode == "dev-unsigned" {
			fmt.Println("  ═══ RESULT: PASS (dev-unsigned, not evidence) ═══")
			fmt.Println()
			fmt.Println("  All structural checks passed, but this bundle is NOT EVIDENCE:")
			fmt.Println("  - signatures=[] and timestamps=[] (mode contract)")
			fmt.Println("  - No trusted timestamp authority attested to its existence")
			fmt.Println("  - Use mode=signed to produce an evidentiary bundle")
		} else {
			if r.Disclosure {
				fmt.Println("  ═══ RESULT: PASS (disclosure) ═══")
				fmt.Println()
				fmt.Println("  Every disclosed event is a byte-identical member of the sealed set,")
				fmt.Println("  proven against the Merkle root the signature and timestamp cover.")
				fmt.Println("  Withheld events reveal only their count and positions.")
				fmt.Println()
				return
			}
			fmt.Println("  ═══ RESULT: PASS ═══")
			fmt.Println()
			fmt.Println("  This bundle is cryptographically intact:")
			fmt.Println("  - Every event matches its recorded hash chain")
			fmt.Println("  - The manifest signature is valid")
			fmt.Println("  - A trusted timestamp authority confirmed this bundle existed")
			fmt.Println("  - The embedded ruleset matches its declared hash")
			fmt.Println("  - Every file in the tree matches the signed files map")
		}
	} else {
		fmt.Println("  ═══ RESULT: FAIL ═══")
		fmt.Println()
		fmt.Println("  This bundle may have been altered. One or more verification")
		fmt.Println("  checks failed. See the details above for specific failures.")
	}
	fmt.Println()
}

// truncHex returns the first n hex chars of s, or s if shorter.
func truncHex(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// JSON returns the verification result as JSON (for machine consumers).
func (r *VerifyResult) JSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// lookupRevocation reads a producer key catalog from disk and returns
// the entry matching `fingerprint` (case-insensitive hex), or nil if
// the fingerprint is not present. A non-existent catalog file is an
// error, the caller asked for revocation enforcement and we refuse
// to silently accept "list missing → nothing revoked".
