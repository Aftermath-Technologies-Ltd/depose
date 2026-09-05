// Package cmd, the anchor check.
//
// A bundle sealed while no timestamp authority could be reached is signed
// and undated. That is a weaker bundle, not an invalid one: the signature
// still binds the content, and `depose anchor` can date it later without
// touching the seal.
//
// The later anchor lives in attestations/anchor.json and carries its own
// countersignature by the sealing key, so a third party cannot bolt a
// token onto someone else's bundle and have it read as the producer's own
// act. This check reports seal time and anchor time separately, and fails
// only when the anchor contradicts the bundle it claims to date.
// See docs/bundle-format.md#anchoring.
package cmd

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/canonical"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/manifest"
)

// anchorPath is where a later anchor is recorded, relative to the bundle.
const anchorPath = "attestations/anchor.json"

// anchorToken is one RFC 3161 token obtained after the seal.
type anchorToken struct {
	Tsa         string `json:"tsa"`
	Timestamp   string `json:"timestamp"`
	TokenBase64 string `json:"tokenBase64"`
	File        string `json:"file"`
}

// anchorCountersignature binds the claim to the sealing key.
type anchorCountersignature struct {
	Scheme       string `json:"scheme"`
	Signature    string `json:"signature"`
	PublicKey    string `json:"publicKey"`
	SignedFields string `json:"signedFields"`
}

// anchorDocument is attestations/anchor.json.
type anchorDocument struct {
	SchemaVersion  int                    `json:"schemaVersion"`
	BundleID       string                 `json:"bundleId"`
	AnchoredAt     string                 `json:"anchoredAt"`
	ManifestSha256 string                 `json:"manifestSha256"`
	Timestamps     []anchorToken          `json:"timestamps"`
	Counter        anchorCountersignature `json:"countersignature"`
}

// loadAnchor reads the anchor document, or returns nil when there is none.
func loadAnchor(bundlePath string) (*anchorDocument, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(bundlePath, filepath.FromSlash(anchorPath)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var doc anchorDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, raw, fmt.Errorf("attestations/anchor.json is malformed: %w", err)
	}
	return &doc, raw, nil
}

// checkAnchorStatus reports when the bundle was sealed and when, if ever,
// it was anchored.
func checkAnchorStatus(ctx *checkContext) []CheckResult {
	const name = "anchor-status"
	m := ctx.manifest
	if m.Producer.Mode == "dev-unsigned" {
		return one(CheckResult{Name: name, Status: StatusSkipped, Detail: "dev-unsigned bundles are not anchored"})
	}

	doc, raw, err := loadAnchor(ctx.bundlePath)
	if err != nil {
		return one(CheckResult{Name: name, Status: StatusFail, Detail: err.Error()})
	}

	if len(m.Timestamps) > 0 {
		if doc == nil {
			return one(CheckResult{
				Name:   name,
				Status: StatusPass,
				Detail: fmt.Sprintf("anchored at seal time: sealed %s, timestamped %s by %s", m.ProducedAt, m.Timestamps[0].Timestamp, m.Timestamps[0].TSA),
			})
		}
		// Both an anchor at seal time and a later one. Not a defect;
		// report both times so a reader sees the sequence.
		return one(CheckResult{
			Name:   name,
			Status: StatusPass,
			Detail: fmt.Sprintf("sealed %s, timestamped %s at seal time, anchored again %s", m.ProducedAt, m.Timestamps[0].Timestamp, doc.AnchoredAt),
		})
	}

	if doc == nil {
		return one(CheckResult{
			Name:   name,
			Status: StatusWarn,
			Detail: fmt.Sprintf(
				"sealed %s and never anchored: the signature binds the content but nothing dates it, "+
					"so the producer's own clock is the only evidence of when this happened. "+
					"Run `depose anchor <bundle>` to add an RFC 3161 token.", m.ProducedAt),
		})
	}

	if problems := anchorProblems(doc, raw, ctx.rawManifest, m); len(problems) > 0 {
		return one(CheckResult{Name: name, Status: StatusFail, Detail: joinProblems(problems)})
	}
	return one(CheckResult{
		Name:   name,
		Status: StatusPass,
		Detail: fmt.Sprintf(
			"sealed %s pending an anchor, anchored %s by %s (countersigned by the sealing key)",
			m.ProducedAt, doc.Timestamps[0].Timestamp, doc.Timestamps[0].Tsa),
	})
}

// anchorProblems checks everything an anchor document has to satisfy to
// count as the producer's own act over this bundle.
func anchorProblems(doc *anchorDocument, raw, rawManifest []byte, m *manifest.Manifest) []string {
	var problems []string

	if doc.BundleID != m.BundleID {
		problems = append(problems, fmt.Sprintf("anchor names bundle %s, this bundle is %s", doc.BundleID, m.BundleID))
	}
	if len(doc.Timestamps) == 0 {
		problems = append(problems, "anchor carries no timestamp")
	}
	if err := checkAnchorManifestBinding(doc, rawManifest); err != nil {
		problems = append(problems, err.Error())
	}
	if err := checkCountersignature(doc, raw); err != nil {
		problems = append(problems, err.Error())
	}
	if err := checkAnchorKey(doc, m); err != nil {
		problems = append(problems, err.Error())
	}
	return problems
}

// checkAnchorManifestBinding proves the anchor dates this manifest and no
// other: the recorded hash must be the hash of this manifest's signing form.
func checkAnchorManifestBinding(doc *anchorDocument, rawManifest []byte) error {
	unsigned, err := manifest.StripSignatureFields(rawManifest)
	if err != nil {
		return fmt.Errorf("cannot rebuild the manifest signing form: %v", err)
	}
	sum := sha256.Sum256(unsigned)
	if hex.EncodeToString(sum[:]) != doc.ManifestSha256 {
		return fmt.Errorf(
			"anchor commits to manifest %s... but this manifest hashes to %s...; the anchor belongs to a different seal",
			truncHex(doc.ManifestSha256, 16), truncHex(hex.EncodeToString(sum[:]), 16))
	}
	return nil
}

// checkCountersignature verifies the Ed25519 countersignature over the
// canonical claim, which is the document with countersignature removed.
func checkCountersignature(doc *anchorDocument, raw []byte) error {
	if doc.Counter.Scheme != "ed25519" {
		return fmt.Errorf("anchor countersignature scheme %q is not ed25519", doc.Counter.Scheme)
	}
	var asMap map[string]interface{}
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return fmt.Errorf("anchor document is malformed: %v", err)
	}
	delete(asMap, "countersignature")
	claim, err := canonical.Marshal(asMap)
	if err != nil {
		return fmt.Errorf("cannot canonicalize the anchor claim: %v", err)
	}

	block, _ := pem.Decode([]byte(doc.Counter.PublicKey))
	if block == nil {
		return fmt.Errorf("anchor countersignature has no PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("anchor countersignature public key does not parse: %v", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("anchor countersignature key is not Ed25519")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Counter.Signature)
	if err != nil {
		return fmt.Errorf("anchor countersignature is not base64")
	}
	if !ed25519.Verify(pub, claim, sig) {
		return fmt.Errorf("anchor countersignature INVALID; the anchor was altered or was not made by this producer")
	}
	return nil
}

// checkAnchorKey requires the countersigning key to be the sealing key.
// Anyone can obtain a timestamp over a public manifest; only the producer
// can say the anchor is theirs.
func checkAnchorKey(doc *anchorDocument, m *manifest.Manifest) error {
	if len(m.Signatures) == 0 {
		return nil
	}
	if doc.Counter.PublicKey != m.Signatures[0].PublicKey {
		return fmt.Errorf("anchor was countersigned by a different key than the one that sealed the bundle")
	}
	return nil
}
