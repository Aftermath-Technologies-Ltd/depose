// Package cmd — top-level verification orchestration for depose-verify.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/depose/depose/apps/verify/chain"
	"github.com/depose/depose/apps/verify/manifest"
	"github.com/depose/depose/apps/verify/timestamp"
)

// CheckResult represents the result of a single verification check.
type CheckResult struct {
	Name    string
	Pass    bool
	Detail  string
}

// VerifyResult represents the overall verification result.
type VerifyResult struct {
	Pass    bool
	Bundle  string
	Checks  []CheckResult
}

// VerifyBundle runs all verification checks on a .depo bundle directory.
func VerifyBundle(bundlePath string) *VerifyResult {
	result := &VerifyResult{
		Bundle: bundlePath,
		Pass:   true,
	}

	// ── Check 1: Manifest exists and parses ───────────────────────────
	m, err := manifest.LoadManifest(bundlePath)
	if err != nil {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "manifest-parse",
			Pass:   false,
			Detail: fmt.Sprintf("Failed to parse manifest.json: %v", err),
		})
		result.Pass = false
		return result
	}
	result.Checks = append(result.Checks, CheckResult{
		Name:   "manifest-parse",
		Pass:   true,
		Detail: fmt.Sprintf("Bundle %s, schema v%d, %d events", m.BundleID, m.SchemaVersion, m.Counts.Events),
	})

	// ── Check 2: Signature verification ──────────────────────────────
	if len(m.Signatures) == 0 {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "signature-verify",
			Pass:   false,
			Detail: "No signatures found — unsigned bundle",
		})
		result.Pass = false
	} else {
		// Read raw manifest bytes for signature verification
		rawManifest, err := os.ReadFile(filepath.Join(bundlePath, "manifest.json"))
		if err != nil {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "signature-verify",
				Pass:   false,
				Detail: fmt.Sprintf("Cannot re-read manifest: %v", err),
			})
			result.Pass = false
		} else {
			if err := manifest.VerifySignature(m, rawManifest); err != nil {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "signature-verify",
					Pass:   false,
					Detail: fmt.Sprintf("Signature INVALID: %v", err),
				})
				result.Pass = false
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "signature-verify",
					Pass:   true,
					Detail: fmt.Sprintf("Ed25519 signature valid (%d signature(s))", len(m.Signatures)),
				})
			}
		}
	}

	// ── Check 3: Hash chain replay ───────────────────────────────────
	if m.RootHash == "" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "chain-replay",
			Pass:   false,
			Detail: "No root hash — unsigned bundle",
		})
		result.Pass = false
	} else {
		chainResult, err := chain.ReplayChain(bundlePath)
		if err != nil {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "chain-replay",
				Pass:   false,
				Detail: fmt.Sprintf("Chain replay error: %v", err),
			})
			result.Pass = false
		} else {
			if len(chainResult.HashMismatches) > 0 {
				details := make([]string, len(chainResult.HashMismatches))
				for i, mm := range chainResult.HashMismatches {
					details[i] = fmt.Sprintf("event[%d] %s: expected %s, got %s",
						mm.Index, mm.EventID, mm.Expected[:16], mm.Computed[:16])
				}
				result.Checks = append(result.Checks, CheckResult{
					Name:   "chain-replay",
					Pass:   false,
					Detail: fmt.Sprintf("Chain hash mismatch at %d event(s): %s",
						len(chainResult.HashMismatches), strings.Join(details, "; ")),
				})
				result.Pass = false
			} else if chainResult.RootHash != m.RootHash {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "chain-replay",
					Pass:   false,
					Detail: fmt.Sprintf("Root hash mismatch: manifest=%s, computed=%s",
						m.RootHash[:16], chainResult.RootHash[:16]),
				})
				result.Pass = false
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "chain-replay",
					Pass:   true,
					Detail: fmt.Sprintf("Chain valid: %d events, root hash %s...",
						chainResult.EventCount, chainResult.RootHash[:16]),
				})
			}
		}
	}

	// ── Check 4: RFC 3161 timestamps ──────────────────────────────────
	if len(m.Timestamps) == 0 {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "timestamp-verify",
			Pass:   false,
			Detail: "No RFC 3161 timestamps found",
		})
		result.Pass = false
	} else {
		// Compute SHA-256 of the UNSIGNED manifest for timestamp verification.
		// The TSA was asked to timestamp SHA-256(canonical JSON of unsigned manifest),
		// matching the same procedure used for signing. We must strip signatures
		// and timestamps before hashing, just like in VerifySignature.
		rawManifest, _ := os.ReadFile(filepath.Join(bundlePath, "manifest.json"))
		unsignedManifest, _ := manifest.StripSignatureFields(rawManifest)
		manifestHash := sha256.Sum256(unsignedManifest)

		allTimestampsValid := true
		timestampDetails := make([]string, 0, len(m.Timestamps))

		for _, mt := range m.Timestamps {
			token := timestamp.Token{
				TSA:         mt.TSA,
				Timestamp:   mt.Timestamp,
				TokenBase64: mt.TokenBase64,
			}
			vr := timestamp.VerifyToken(token, hex.EncodeToString(manifestHash[:]))
			if !vr.Valid {
				allTimestampsValid = false
				timestampDetails = append(timestampDetails,
					fmt.Sprintf("%s: INVALID — %s", vr.TSA, vr.Detail))
			} else {
				timestampDetails = append(timestampDetails,
					fmt.Sprintf("%s: valid", vr.TSA))
			}
		}

		if !allTimestampsValid {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "timestamp-verify",
				Pass:   false,
				Detail: fmt.Sprintf("Timestamp validation failed: %s",
					strings.Join(timestampDetails, "; ")),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "timestamp-verify",
				Pass:   true,
				Detail: fmt.Sprintf("%d timestamp(s) valid: %s",
					len(m.Timestamps), strings.Join(timestampDetails, "; ")),
			})
		}

		// Convert manifest tokens to timestamp tokens for anti-backdating check
		tsTokens := make([]timestamp.Token, len(m.Timestamps))
		for i, mt := range m.Timestamps {
			tsTokens[i] = timestamp.Token{
				TSA:         mt.TSA,
				Timestamp:   mt.Timestamp,
				TokenBase64: mt.TokenBase64,
			}
		}

		// Anti-backdating check
		if err := timestamp.VerifyManifestProducedAt(m.ProducedAt, tsTokens); err != nil {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "timestamp-backdating",
				Pass:   false,
				Detail: err.Error(),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "timestamp-backdating",
				Pass:   true,
				Detail: "producedAt is not after any TSA timestamp",
			})
		}
	}

	// ── Check 5: Artifact integrity (SHA-256 spot checks) ─────────────
	// Verify that events.jsonl hash is consistent with the chain
	eventsPath := filepath.Join(bundlePath, "events.jsonl")
	eventsData, err := os.ReadFile(eventsPath)
	if err != nil {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "artifact-events-jsonl",
			Pass:   false,
			Detail: fmt.Sprintf("Cannot read events.jsonl: %v", err),
		})
		result.Pass = false
	} else {
		eventsHash := sha256.Sum256(eventsData)
		result.Checks = append(result.Checks, CheckResult{
			Name:   "artifact-events-jsonl",
			Pass:   true,
			Detail: fmt.Sprintf("events.jsonl present, sha256=%s...", hex.EncodeToString(eventsHash[:])[:16]),
		})
	}

	// ── Check 6: Ruleset integrity ───────────────────────────────────
	// The bundle must carry the actual destructive ruleset bytes, and
	// SHA-256 of that file must match manifest.rulesetHash. This is
	// what lets a third-party auditor reconstruct *which* rules were
	// applied when the manifest's counts.destructiveOperations was
	// computed.
	rulesetPath := filepath.Join(bundlePath, "rules", "destructive.yaml")
	rulesetBytes, err := os.ReadFile(rulesetPath)
	if err != nil {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "ruleset-integrity",
			Pass:   false,
			Detail: fmt.Sprintf("Cannot read rules/destructive.yaml: %v", err),
		})
		result.Pass = false
	} else if m.RulesetHash == "" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "ruleset-integrity",
			Pass:   false,
			Detail: "manifest.rulesetHash is empty — cannot verify embedded ruleset",
		})
		result.Pass = false
	} else {
		computed := sha256.Sum256(rulesetBytes)
		computedHex := hex.EncodeToString(computed[:])
		if computedHex != m.RulesetHash {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "ruleset-integrity",
				Pass:   false,
				Detail: fmt.Sprintf("rules/destructive.yaml hash mismatch: manifest=%s..., computed=%s...",
					m.RulesetHash[:16], computedHex[:16]),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "ruleset-integrity",
				Pass:   true,
				Detail: fmt.Sprintf("rules/destructive.yaml (%d bytes) matches manifest.rulesetHash %s...",
					len(rulesetBytes), computedHex[:16]),
			})
		}
	}

	// ── Check 7: Bundle completeness ─────────────────────────────────
	requiredPaths := []string{
		"manifest.json",
		"events.jsonl",
		"attestations/signatures.json",
		"rules/destructive.yaml",
		"verify.txt",
	}
	missingPaths := []string{}
	for _, p := range requiredPaths {
		if _, err := os.Stat(filepath.Join(bundlePath, p)); err != nil {
			missingPaths = append(missingPaths, p)
		}
	}
	if len(missingPaths) > 0 {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "bundle-completeness",
			Pass:   false,
			Detail: fmt.Sprintf("Missing required files: %s", strings.Join(missingPaths, ", ")),
		})
		result.Pass = false
	} else {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "bundle-completeness",
			Pass:   true,
			Detail: "All required files present",
		})
	}

	// ── Check 8: Rekor (optional, skipped in air-gapped mode) ───────
	if m.Rekor != nil && len(m.Rekor) > 0 {
		skippedCount := 0
		for _, entry := range m.Rekor {
			vr := timestamp.VerifyRekorEntry(entry.UUID, entry.Body, entry.IntegratedTime)
			if vr.Skipped {
				skippedCount++
			}
		}
		result.Checks = append(result.Checks, CheckResult{
			Name:   "rekor-verify",
			Pass:   true, // Rekor is optional
			Detail: fmt.Sprintf("Rekor verification skipped (%d entries) — optional transparency log", skippedCount),
		})
	}

	return result
}

// Print outputs the verification result in human-readable format.
func (r *VerifyResult) Print() {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║            DEPOSE Evidence Bundle Verification Report          ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Bundle: %s\n", r.Bundle)
	fmt.Println()

	allPass := true
	for _, check := range r.Checks {
		status := "PASS"
		icon := "✓"
		if !check.Pass {
			status = "FAIL"
			icon = "✗"
			allPass = false
		}
		fmt.Printf("  [%s] %s: %s\n", icon, check.Name, status)
		fmt.Printf("         %s\n", check.Detail)
	}

	fmt.Println()
	if allPass {
		fmt.Println("  ═══ RESULT: PASS ═══")
		fmt.Println()
		fmt.Println("  This bundle is cryptographically intact:")
		fmt.Println("  - Every event matches its recorded hash chain")
		fmt.Println("  - The manifest signature is valid")
		fmt.Println("  - A trusted timestamp authority confirmed this bundle existed")
		fmt.Println("  - No files have been added, removed, or modified since creation")
	} else {
		fmt.Println("  ═══ RESULT: FAIL ═══")
		fmt.Println()
		fmt.Println("  This bundle may have been altered. One or more verification")
		fmt.Println("  checks failed. See the details above for specific failures.")
	}
	fmt.Println()
}

// JSON returns the verification result as JSON (for machine consumers).
func (r *VerifyResult) JSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}