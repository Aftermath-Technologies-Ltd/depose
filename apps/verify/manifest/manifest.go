// Package manifest, parse and represent a DEPOSE bundle manifest.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/canonical"
)

// Manifest represents the manifest.json structure.
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	BundleID      string       `json:"bundleId"`
	ProducedAt    string       `json:"producedAt"`
	Producer      ProducerInfo `json:"producer"`
	Session       SessionInfo  `json:"session"`
	RootHash      string       `json:"rootHash"`
	// MerkleRoot is the RFC 6962 tree head over the chain hashes. Empty
	// on bundles sealed before the tree existed.
	MerkleRoot string `json:"merkleRoot,omitempty"`
	// EventsJsonlSha256 is the SHA-256 (lowercase hex) of the literal
	// UTF-8 bytes of events.jsonl. Optional on older bundles; verifier
	// requires it in `signed` mode.
	EventsJsonlSha256 string `json:"eventsJsonlSha256,omitempty"`
	// Files pins every file in the bundle tree except manifest.json,
	// attestations/signatures.json, and the .tsr files. Nil on
	// schemaVersion 2 bundles, which predate it.
	Files       map[string]FileEntry `json:"files,omitempty"`
	Signatures  []SignatureBlock     `json:"signatures"`
	Timestamps  []Rfc3161Token       `json:"timestamps"`
	Counts      Counts               `json:"counts"`
	RulesetHash string               `json:"rulesetHash"`
	// AnchorStatus is "anchored" or "pending". Outside the signed form,
	// like Signatures and Timestamps, because it is written after the
	// signature is made and changes again when a pending bundle is
	// anchored later. It is a label; the anchor check derives the real
	// state from Timestamps and attestations/anchor.json.
	AnchorStatus string `json:"anchorStatus,omitempty"`
}

type ProducerInfo struct {
	Tool           string   `json:"tool"`
	Version        string   `json:"version"`
	Mode           string   `json:"mode"`
	KeyFingerprint string   `json:"keyFingerprint,omitempty"`
	Host           HostInfo `json:"host"`
}

type HostInfo struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	NodeVersion string `json:"nodeVersion"`
	Kernel      string `json:"kernel"`
}

type SessionInfo struct {
	AgentID   string           `json:"agentId"`
	SessionID string           `json:"sessionId"`
	StartedAt string           `json:"startedAt"`
	EndedAt   string           `json:"endedAt"`
	Host      *SessionHostInfo `json:"host,omitempty"`
}

// SessionHostInfo records the capture environment of the agent session.
// Fields are nullable because they may be unavailable during
// reconstruction. Added in schemaVersion 2.
type SessionHostInfo struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	NodeVersion string `json:"nodeVersion"`
	Kernel      string `json:"kernel"`
}

// FileEntry is one files-map entry: the file's SHA-256 and byte length.
type FileEntry struct {
	Sha256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type SignatureBlock struct {
	Scheme       string `json:"scheme"`
	Signature    string `json:"signature"`
	PublicKey    string `json:"publicKey,omitempty"`
	SignedFields string `json:"signedFields"`
}

type Rfc3161Token struct {
	TSA         string `json:"tsa"`
	Timestamp   string `json:"timestamp"`
	TokenBase64 string `json:"tokenBase64"`
}

type Counts struct {
	Events                int `json:"events"`
	DestructiveOperations int `json:"destructiveOperations"`
	Gaps                  int `json:"gaps"`
	ArtifactsPre          int `json:"artifactsPre"`
	ArtifactsPost         int `json:"artifactsPost"`
	// CapturesAttributed and CapturesExcluded record how much of the
	// producer's capture store went into this bundle and how much was left
	// out as unattributable to the session. Bundles produced before these
	// fields existed omit them and decode as zero, which is why they are
	// reported rather than asserted on.
	CapturesAttributed int `json:"capturesAttributed"`
	CapturesExcluded   int `json:"capturesExcluded"`
}

// LoadManifest reads and parses manifest.json from the bundle directory.
func LoadManifest(bundleDir string) (*Manifest, error) {
	path := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest.json: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest.json: %w", err)
	}

	return &m, nil
}

// VerifySignature checks the Ed25519 signature against the manifest.
//
// The signature is computed over the SHA-256 of the canonical JSON of the
// manifest with signatures=[] and timestamps=[] (the "unsigned form").
// This avoids the self-referential signature problem. When verifying, we
// must reconstruct the same unsigned manifest to compute the expected hash.
func VerifySignature(m *Manifest, rawManifestBytes []byte) error {
	if len(m.Signatures) == 0 {
		return fmt.Errorf("no signatures found, unsigned bundle")
	}

	for i, sig := range m.Signatures {
		if sig.Scheme != "ed25519" {
			return fmt.Errorf("signature[%d]: unsupported scheme %q", i, sig.Scheme)
		}

		if sig.PublicKey == "" {
			return fmt.Errorf("signature[%d]: missing public key", i)
		}

		// Decode the PEM public key with the stdlib decoder.
		block, _ := pem.Decode([]byte(sig.PublicKey))
		if block == nil {
			return fmt.Errorf("signature[%d]: no PEM block in publicKey", i)
		}
		pubKeyBytes := block.Bytes

		// Parse the Ed25519 public key
		pub, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("signature[%d]: parse public key: %w", i, err)
		}

		ed25519Pub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("signature[%d]: not an Ed25519 key", i)
		}

		sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			return fmt.Errorf("signature[%d]: decode base64: %w", i, err)
		}

		// Reconstruct the unsigned-form canonical JSON bytes that the
		// producer signed. Ed25519 (pure) hashes the message itself
		// per RFC 8032, so we sign/verify the canonical JSON bytes
		// directly, no pre-hash, no hex encoding step.
		unsignedManifest, err := StripSignatureFields(rawManifestBytes)
		if err != nil {
			return fmt.Errorf("signature[%d]: prepare unsigned manifest: %w", i, err)
		}

		if !ed25519.Verify(ed25519Pub, unsignedManifest, sigBytes) {
			return fmt.Errorf("signature[%d]: INVALID; signature does not match manifest", i)
		}
	}

	return nil
}

// StripSignatureFields removes the signatures, timestamps, and
// anchorStatus fields from the manifest JSON to produce the "unsigned
// form" for signature verification. All three are written after the
// signature is made, and anchorStatus changes again when a pending
// bundle is anchored later.
// Exported so cmd/verify.go can reuse it for timestamp verification.
//
// The output is re-canonicalized through the JCS writer so the bytes
// match TypeScript's `serializeManifestForSigning` exactly. Using
// stdlib `json.Marshal` here would HTML-escape `<`, `>`, `&` (Go's
// default) and silently diverge from the producer.
func StripSignatureFields(manifestJSON []byte) ([]byte, error) {
	var m map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(manifestJSON))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest for signing: %w", err)
	}
	m["signatures"] = []interface{}{}
	m["timestamps"] = []interface{}{}
	delete(m, "anchorStatus")
	return canonical.Marshal(m)
}
