// Package manifest — parse and represent a DEPOSE bundle manifest.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/depose/depose/apps/verify/canonical"
)

// Manifest represents the manifest.json structure.
type Manifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	BundleID      string           `json:"bundleId"`
	ProducedAt    string           `json:"producedAt"`
	Producer      ProducerInfo     `json:"producer"`
	Session       SessionInfo      `json:"session"`
	RootHash      string           `json:"rootHash"`
	Signatures    []SignatureBlock `json:"signatures"`
	Timestamps    []Rfc3161Token   `json:"timestamps"`
	Rekor         []RekorEntry     `json:"rekor,omitempty"`
	Counts        Counts           `json:"counts"`
	RulesetHash   string           `json:"rulesetHash"`
}

type ProducerInfo struct {
	Tool    string   `json:"tool"`
	Version string   `json:"version"`
	Mode    string   `json:"mode"`
	Host    HostInfo `json:"host"`
}

type HostInfo struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Kernel string `json:"kernel"`
}

type SessionInfo struct {
	AgentID   string `json:"agentId"`
	SessionID string `json:"sessionId"`
	StartedAt string `json:"startedAt"`
	EndedAt   string `json:"endedAt"`
}

type SignatureBlock struct {
	Scheme      string `json:"scheme"`
	Signature   string `json:"signature"`
	PublicKey   string `json:"publicKey,omitempty"`
	FulcioCert  string `json:"fulcioCert,omitempty"`
	SignedFields string `json:"signedFields"`
}

type Rfc3161Token struct {
	TSA         string `json:"tsa"`
	Timestamp   string `json:"timestamp"`
	TokenBase64 string `json:"tokenBase64"`
}

type RekorEntry struct {
	UUID           string `json:"uuid"`
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
}

type Counts struct {
	Events               int `json:"events"`
	DestructiveOperations int `json:"destructiveOperations"`
	Gaps                 int `json:"gaps"`
	ArtifactsPre         int `json:"artifactsPre"`
	ArtifactsPost        int `json:"artifactsPost"`
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
		return fmt.Errorf("no signatures found — unsigned bundle")
	}

	for i, sig := range m.Signatures {
		if sig.Scheme != "ed25519" {
			return fmt.Errorf("signature[%d]: unsupported scheme %q", i, sig.Scheme)
		}

		if sig.PublicKey == "" {
			return fmt.Errorf("signature[%d]: missing public key", i)
		}

		// Decode the PEM public key
		pubKeyBytes, err := decodePEM([]byte(sig.PublicKey))
		if err != nil {
			return fmt.Errorf("signature[%d]: decode public key PEM: %w", i, err)
		}

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
		// directly — no pre-hash, no hex encoding step.
		unsignedManifest, err := StripSignatureFields(rawManifestBytes)
		if err != nil {
			return fmt.Errorf("signature[%d]: prepare unsigned manifest: %w", i, err)
		}

		if !ed25519.Verify(ed25519Pub, unsignedManifest, sigBytes) {
			return fmt.Errorf("signature[%d]: INVALID — signature does not match manifest", i)
		}
	}

	return nil
}

// StripSignatureFields removes the signatures and timestamps fields from
// the manifest JSON to produce the "unsigned form" for signature verification.
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
	return canonical.Marshal(m)
}

// decodePEM extracts the DER bytes from a PEM block.
func decodePEM(pemData []byte) ([]byte, error) {
	// Simple PEM decoder — find BEGIN/END markers and base64-decode
	// This avoids importing encoding/pem which strips headers we want to preserve
	str := string(pemData)
	beginMarker := "-----BEGIN "
	endMarker := "-----END "

	beginIdx := 0
	for beginIdx < len(str) {
		idx := indexOf(str, beginMarker, beginIdx)
		if idx == -1 {
			break
		}

		// Find the end of the type line
		typeEnd := indexOf(str, "-----\n", idx)
		if typeEnd == -1 {
			break
		}

		// Find END marker
		endIdx := indexOf(str, endMarker, typeEnd)
		if endIdx == -1 {
			break
		}

		// Extract base64 between markers
		dataStart := typeEnd + len("-----\n")
		dataEnd := endIdx

		return base64.StdEncoding.DecodeString(str[dataStart:dataEnd])
	}

	return nil, fmt.Errorf("no PEM block found")
}

// indexOf returns the index of substr in s starting from start.
func indexOf(s, substr string, start int) int {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}