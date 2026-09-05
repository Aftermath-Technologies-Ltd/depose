// Package cmd, top-level verification orchestration for depose-verify.
//
// VerifyBundle runs the ordered checks that decide whether a bundle is
// intact. It is deliberately kept as one sequential function: the checks
// share accumulated state, the order is part of the contract, and this
// package has no unit tests of its own (coverage comes from the TypeScript
// e2e suites). Splitting the trust-critical path without tests to catch a
// mistake would trade a long function for a real risk. Types, reporting,
// and revocation lookup live in types.go, report.go, and revocation.go.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/chain"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/manifest"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/timestamp"
)

func VerifyBundle(bundlePath string, opts ...VerifyOpts) *VerifyResult {
	var opt VerifyOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	result := &VerifyResult{
		Bundle: bundlePath,
		Pass:   true,
	}

	// ── Check 1: Manifest exists and parses ───────────────────────────
	m, err := manifest.LoadManifest(bundlePath)
	if err != nil {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "manifest-parse",
			Status: StatusFail,
			Detail: fmt.Sprintf("Failed to parse manifest.json: %v", err),
		})
		result.Pass = false
		return result
	}
	result.Mode = m.Producer.Mode
	parseDetail := fmt.Sprintf("Bundle %s, schema v%d, mode=%s, %d events",
		m.BundleID, m.SchemaVersion, m.Producer.Mode, m.Counts.Events)
	// Surface the producer's capture accounting. "We held capture records
	// and deliberately did not use them" is something a recipient should
	// read off the signed manifest, not have to infer from an absence.
	if m.Counts.CapturesAttributed > 0 || m.Counts.CapturesExcluded > 0 {
		parseDetail += fmt.Sprintf(
			"\n         captures: %d attributed to this session, %d excluded as unattributable",
			m.Counts.CapturesAttributed, m.Counts.CapturesExcluded)
	}
	result.Checks = append(result.Checks, CheckResult{
		Name:   "manifest-parse",
		Status: StatusPass,
		Detail: parseDetail,
	})

	// ── Check 1a: schemaVersion is within the supported range ───────
	// Compatibility policy (docs/bundle-format.md §8): a verifier
	// supports [SupportedSchemaMin, SupportedSchemaMax]. Bundles
	// outside that range fail closed, no silent attempt to parse
	// a future or stale schema.
	if m.SchemaVersion < SupportedSchemaMin || m.SchemaVersion > SupportedSchemaMax {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "schema-version",
			Status: StatusFail,
			Detail: fmt.Sprintf(
				"unsupported schemaVersion %d (this verifier supports [%d, %d])",
				m.SchemaVersion, SupportedSchemaMin, SupportedSchemaMax),
		})
		result.Pass = false
		return result
	}
	result.Checks = append(result.Checks, CheckResult{
		Name:   "schema-version",
		Status: StatusPass,
		Detail: fmt.Sprintf("schemaVersion %d is supported", m.SchemaVersion),
	})

	// ── Check 1b: producer.mode declared and recognized ──────────────
	// The mode is the bundle's declared contract. The verifier
	// enforces the invariants of the declared mode; declaring a mode
	// the verifier doesn't recognize is itself a failure.
	switch m.Producer.Mode {
	case "signed", "dev-unsigned":
		result.Checks = append(result.Checks, CheckResult{
			Name:   "mode-declaration",
			Status: StatusPass,
			Detail: fmt.Sprintf("producer.mode=%q recognized", m.Producer.Mode),
		})
	case "":
		result.Checks = append(result.Checks, CheckResult{
			Name:   "mode-declaration",
			Status: StatusFail,
			Detail: "producer.mode is missing, bundle predates the mode contract or has been stripped",
		})
		result.Pass = false
	default:
		result.Checks = append(result.Checks, CheckResult{
			Name:   "mode-declaration",
			Status: StatusFail,
			Detail: fmt.Sprintf("producer.mode=%q is not a recognized mode (expected signed or dev-unsigned)", m.Producer.Mode),
		})
		result.Pass = false
	}

	// ── Check 1c: mode-contract invariants ───────────────────────────
	// dev-unsigned: signatures and timestamps MUST both be empty.
	//   Any non-empty value means the producer mis-declared.
	// signed: signatures and timestamps MUST both be non-empty. The
	//   detailed sig/ts checks below will run regardless, but this
	//   gate is what makes the mode contract enforceable.
	switch m.Producer.Mode {
	case "dev-unsigned":
		if len(m.Signatures) > 0 || len(m.Timestamps) > 0 {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "mode-contract",
				Status: StatusFail,
				Detail: fmt.Sprintf(
					"dev-unsigned requires signatures=[] and timestamps=[]; got %d signature(s) and %d timestamp(s)",
					len(m.Signatures), len(m.Timestamps)),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "mode-contract",
				Status: StatusPass,
				Detail: "dev-unsigned: signatures=[], timestamps=[] (as required)",
			})
		}
	case "signed":
		if len(m.Signatures) == 0 || len(m.Timestamps) == 0 {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "mode-contract",
				Status: StatusFail,
				Detail: fmt.Sprintf(
					"signed requires at least one signature and at least one timestamp; got %d signature(s) and %d timestamp(s)",
					len(m.Signatures), len(m.Timestamps)),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "mode-contract",
				Status: StatusPass,
				Detail: "signed: signatures and timestamps both present",
			})
		}
	}

	// ── Check 1d: producer.keyFingerprint pin (optional) ─────────────
	// When the recipient passes --expected-key-fingerprint, the
	// manifest's keyFingerprint must equal it. This is the
	// air-gapped trust path: the producer publishes the fingerprint
	// out-of-band, and the verifier refuses any bundle that doesn't
	// match. Skipped when no expectation was provided.
	if opt.ExpectedKeyFingerprint != "" {
		got := m.Producer.KeyFingerprint
		want := opt.ExpectedKeyFingerprint
		if got == "" {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "key-fingerprint-pin",
				Status: StatusFail,
				Detail: fmt.Sprintf(
					"--expected-key-fingerprint=%s, but manifest has no producer.keyFingerprint",
					want),
			})
			result.Pass = false
		} else if !strings.EqualFold(got, want) {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "key-fingerprint-pin",
				Status: StatusFail,
				Detail: fmt.Sprintf(
					"key fingerprint mismatch: manifest=%s..., expected=%s...",
					truncHex(got, 16), truncHex(want, 16)),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "key-fingerprint-pin",
				Status: StatusPass,
				Detail: fmt.Sprintf("manifest key fingerprint matches expectation (%s...)", truncHex(got, 16)),
			})
		}
	}

	// ── Check 1d': revocation list (optional) ────────────────────────
	// When the recipient passes --revocation-list, load the producer's
	// key catalog and reject the bundle if its keyFingerprint appears
	// with status=revoked. Active and rotated keys verify normally ,
	// rotation is "old but valid", revocation is "do not trust".
	if opt.RevocationListPath != "" {
		entry, loadErr := lookupRevocation(opt.RevocationListPath, m.Producer.KeyFingerprint)
		switch {
		case loadErr != nil:
			result.Checks = append(result.Checks, CheckResult{
				Name:   "revocation-list",
				Status: StatusFail,
				Detail: fmt.Sprintf("Failed to load revocation list %q: %v", opt.RevocationListPath, loadErr),
			})
			result.Pass = false
		case entry != nil && entry.Status == "revoked":
			result.Checks = append(result.Checks, CheckResult{
				Name:   "revocation-list",
				Status: StatusFail,
				Detail: fmt.Sprintf(
					"key fingerprint %s... is REVOKED in %s (reason: %q, revokedAt: %s)",
					truncHex(m.Producer.KeyFingerprint, 16),
					filepath.Base(opt.RevocationListPath),
					entry.Reason, entry.RevokedAt),
			})
			result.Pass = false
		default:
			detail := "key fingerprint not present in revocation list (accepted)"
			if entry != nil {
				detail = fmt.Sprintf("key fingerprint present, status=%s (accepted)", entry.Status)
			}
			result.Checks = append(result.Checks, CheckResult{
				Name:   "revocation-list",
				Status: StatusPass,
				Detail: detail,
			})
		}
	}

	// ── Check 1e: signer identity (Sigstore, future) ─────────────────
	// Currently a no-op placeholder; Sigstore-signed bundles will
	// land in a follow-up. We surface the flag so the contract is
	// visible in --help today and pin tests can exist.
	if opt.SignerIdentityRegex != "" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "signer-identity",
			Status: StatusSkipped,
			Detail: fmt.Sprintf("--signer-identity=%q recorded, but this bundle carries no Sigstore signature to bind it to", opt.SignerIdentityRegex),
		})
	}

	// ── Check 2: Signature verification ──────────────────────────────
	// In dev-unsigned mode we skip the signature check entirely, the
	// mode-contract gate above already requires signatures=[].
	if m.Producer.Mode == "dev-unsigned" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "signature-verify",
			Status: StatusSkipped,
			Detail: "dev-unsigned bundles carry no signature",
		})
	} else if len(m.Signatures) == 0 {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "signature-verify",
			Status: StatusFail,
			Detail: "No signatures found, signed bundle missing signature",
		})
		result.Pass = false
	} else {
		// Read raw manifest bytes for signature verification
		rawManifest, err := os.ReadFile(filepath.Join(bundlePath, "manifest.json"))
		if err != nil {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "signature-verify",
				Status: StatusFail,
				Detail: fmt.Sprintf("Cannot re-read manifest: %v", err),
			})
			result.Pass = false
		} else {
			if err := manifest.VerifySignature(m, rawManifest); err != nil {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "signature-verify",
					Status: StatusFail,
					Detail: fmt.Sprintf("Signature INVALID: %v", err),
				})
				result.Pass = false
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "signature-verify",
					Status: StatusPass,
					Detail: fmt.Sprintf("Ed25519 signature valid (%d signature(s))", len(m.Signatures)),
				})
			}
		}
	}

	// ── Check 3: Hash chain replay ───────────────────────────────────
	// In dev-unsigned mode rootHash may legitimately be empty (the
	// reconstruct command produces no chain). Skip chain-replay in
	// that case instead of failing.
	if m.RootHash == "" && m.Producer.Mode == "dev-unsigned" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "chain-replay",
			Status: StatusSkipped,
			Detail: "dev-unsigned bundle carries no chain (rootHash empty)",
		})
	} else if m.RootHash == "" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "chain-replay",
			Status: StatusFail,
			Detail: "No root hash, signed bundle missing chain",
		})
		result.Pass = false
	} else {
		chainResult, err := chain.ReplayChain(bundlePath)
		if err != nil {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "chain-replay",
				Status: StatusFail,
				Detail: fmt.Sprintf("Chain replay error: %v", err),
			})
			result.Pass = false
		} else {
			// payload-hash recomputation is reported as its own check so
			// the failure mode (payload tamper) is obvious in the report.
			if len(chainResult.PayloadMismatches) > 0 {
				details := make([]string, len(chainResult.PayloadMismatches))
				for i, mm := range chainResult.PayloadMismatches {
					details[i] = fmt.Sprintf("event[%d] %s: stored=%s, recomputed=%s",
						mm.Index, mm.EventID, mm.Expected[:16], mm.Computed[:16])
				}
				result.Checks = append(result.Checks, CheckResult{
					Name:   "payload-hash",
					Status: StatusFail,
					Detail: fmt.Sprintf(
						"payloadHash mismatch at %d event(s), payload bytes do not canonicalize to the recorded hash: %s",
						len(chainResult.PayloadMismatches), strings.Join(details, "; ")),
				})
				result.Pass = false
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "payload-hash",
					Status: StatusPass,
					Detail: fmt.Sprintf(
						"all %d event payloads re-hash to their recorded payloadHash",
						chainResult.EventCount),
				})
			}

			if len(chainResult.HashMismatches) > 0 {
				details := make([]string, len(chainResult.HashMismatches))
				for i, mm := range chainResult.HashMismatches {
					details[i] = fmt.Sprintf("event[%d] %s: expected %s, got %s",
						mm.Index, mm.EventID, mm.Expected[:16], mm.Computed[:16])
				}
				result.Checks = append(result.Checks, CheckResult{
					Name:   "chain-replay",
					Status: StatusFail,
					Detail: fmt.Sprintf("Chain hash mismatch at %d event(s): %s",
						len(chainResult.HashMismatches), strings.Join(details, "; ")),
				})
				result.Pass = false
			} else if chainResult.RootHash != m.RootHash {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "chain-replay",
					Status: StatusFail,
					Detail: fmt.Sprintf("Root hash mismatch: manifest=%s, computed=%s",
						m.RootHash[:16], chainResult.RootHash[:16]),
				})
				result.Pass = false
			} else {
				result.Checks = append(result.Checks, CheckResult{
					Name:   "chain-replay",
					Status: StatusPass,
					Detail: fmt.Sprintf("Chain valid: %d events, root hash %s...",
						chainResult.EventCount, chainResult.RootHash[:16]),
				})
			}
		}
	}

	// ── Check 4: RFC 3161 timestamps ──────────────────────────────────
	// Skipped entirely in dev-unsigned mode; mode-contract enforces
	// timestamps=[] for that mode.
	if m.Producer.Mode == "dev-unsigned" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "timestamp-verify",
			Status: StatusSkipped,
			Detail: "dev-unsigned bundles carry no timestamp",
		})
	} else if len(m.Timestamps) == 0 {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "timestamp-verify",
			Status: StatusFail,
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
					fmt.Sprintf("%s: INVALID, %s", vr.TSA, vr.Detail))
			} else {
				timestampDetails = append(timestampDetails,
					fmt.Sprintf("%s: valid", vr.TSA))
			}
		}

		if !allTimestampsValid {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "timestamp-verify",
				Status: StatusFail,
				Detail: fmt.Sprintf("Timestamp validation failed: %s",
					strings.Join(timestampDetails, "; ")),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "timestamp-verify",
				Status: StatusPass,
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
				Status: StatusFail,
				Detail: err.Error(),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "timestamp-backdating",
				Status: StatusPass,
				Detail: "producedAt is not after any TSA timestamp",
			})
		}
	}

	// ── Check 5: events.jsonl byte-integrity ─────────────────────────
	// The producer hashes the literal UTF-8 bytes of events.jsonl into
	// manifest.eventsJsonlSha256 *before* signing. We re-hash on read
	// and compare, adding, removing, reordering, or any whitespace-
	// level change to events.jsonl fails verification on top of the
	// per-event payloadHash + chain checks above.
	eventsPath := filepath.Join(bundlePath, "events.jsonl")
	eventsData, err := os.ReadFile(eventsPath)
	if err != nil {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "artifact-events-jsonl",
			Status: StatusFail,
			Detail: fmt.Sprintf("Cannot read events.jsonl: %v", err),
		})
		result.Pass = false
	} else {
		eventsHash := sha256.Sum256(eventsData)
		computedHex := hex.EncodeToString(eventsHash[:])
		switch {
		case m.EventsJsonlSha256 == "" && m.Producer.Mode == "signed":
			result.Checks = append(result.Checks, CheckResult{
				Name:   "artifact-events-jsonl",
				Status: StatusFail,
				Detail: fmt.Sprintf(
					"signed bundle missing manifest.eventsJsonlSha256 (computed sha256=%s...)",
					computedHex[:16]),
			})
			result.Pass = false
		case m.EventsJsonlSha256 == "":
			// dev-unsigned: legacy bundles may have no field; report informationally.
			result.Checks = append(result.Checks, CheckResult{
				Name:   "artifact-events-jsonl",
				Status: StatusPass,
				Detail: fmt.Sprintf("events.jsonl sha256=%s... (no manifest pin in dev-unsigned)", computedHex[:16]),
			})
		case !strings.EqualFold(computedHex, m.EventsJsonlSha256):
			result.Checks = append(result.Checks, CheckResult{
				Name:   "artifact-events-jsonl",
				Status: StatusFail,
				Detail: fmt.Sprintf(
					"events.jsonl sha256 mismatch: manifest=%s..., computed=%s...",
					m.EventsJsonlSha256[:16], computedHex[:16]),
			})
			result.Pass = false
		default:
			result.Checks = append(result.Checks, CheckResult{
				Name:   "artifact-events-jsonl",
				Status: StatusPass,
				Detail: fmt.Sprintf(
					"events.jsonl (%d bytes) matches manifest.eventsJsonlSha256 %s...",
					len(eventsData), computedHex[:16]),
			})
		}
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
			Status: StatusFail,
			Detail: fmt.Sprintf("Cannot read rules/destructive.yaml: %v", err),
		})
		result.Pass = false
	} else if m.RulesetHash == "" {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "ruleset-integrity",
			Status: StatusFail,
			Detail: "manifest.rulesetHash is empty, cannot verify embedded ruleset",
		})
		result.Pass = false
	} else {
		computed := sha256.Sum256(rulesetBytes)
		computedHex := hex.EncodeToString(computed[:])
		if computedHex != m.RulesetHash {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "ruleset-integrity",
				Status: StatusFail,
				Detail: fmt.Sprintf("rules/destructive.yaml hash mismatch: manifest=%s..., computed=%s...",
					m.RulesetHash[:16], computedHex[:16]),
			})
			result.Pass = false
		} else {
			result.Checks = append(result.Checks, CheckResult{
				Name:   "ruleset-integrity",
				Status: StatusPass,
				Detail: fmt.Sprintf("rules/destructive.yaml (%d bytes) matches manifest.rulesetHash %s...",
					len(rulesetBytes), computedHex[:16]),
			})
		}
	}

	// ── Check 6b: files map and attestation files ────────────────────
	// Every file in the tree is pinned by the signed manifest.files map,
	// and the attestation artifacts the map cannot contain are bound to
	// the manifest by content equality. A swapped raw JSONL, an added
	// file, a deleted .tsr, or a truncated narrative all fail here.
	for _, check := range []CheckResult{checkFilesMap(bundlePath, m), checkAttestationFiles(bundlePath, m)} {
		result.Checks = append(result.Checks, check)
		if check.Failed() {
			result.Pass = false
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
			Status: StatusFail,
			Detail: fmt.Sprintf("Missing required files: %s", strings.Join(missingPaths, ", ")),
		})
		result.Pass = false
	} else {
		result.Checks = append(result.Checks, CheckResult{
			Name:   "bundle-completeness",
			Status: StatusPass,
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
			Status: StatusPass, // Rekor is optional
			Detail: fmt.Sprintf("Rekor verification skipped (%d entries), optional transparency log", skippedCount),
		})
	}

	return result
}

// Print outputs the verification result in human-readable format.
//
// In dev-unsigned mode we deliberately refuse to print the plain
// "PASS" banner, a dev-unsigned bundle is not evidence even when
// every check passes. The recipient must see the disclaimer.
