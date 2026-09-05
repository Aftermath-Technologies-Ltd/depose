package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/manifest"
)

// The shared manifest vectors in tests/conformance pin the files map and
// the unsigned canonical form the producer signs. For each vector the
// verifier must accept the materialized tree against the given map (and
// reject it when a file is touched), and derive the same unsigned bytes
// and hash from a manifest that carries signatures and timestamps.

type manifestVector struct {
	Name                      string                        `json:"name"`
	Tree                      map[string]string             `json:"tree"`
	ExpectedFilesMap          map[string]manifest.FileEntry `json:"expectedFilesMap"`
	Manifest                  json.RawMessage               `json:"manifest"`
	ExpectedUnsignedCanonical string                        `json:"expectedUnsignedCanonical"`
	ExpectedManifestHash      string                        `json:"expectedManifestHash"`
}

func loadManifestVectors(t *testing.T) []manifestVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "conformance", "manifest-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []manifestVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return doc.Vectors
}

func materialize(t *testing.T, tree map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range tree {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestManifestConformance(t *testing.T) {
	for _, v := range loadManifestVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			dir := materialize(t, v.Tree)
			m := &manifest.Manifest{SchemaVersion: 3, Files: v.ExpectedFilesMap}
			if r := checkFilesMap(dir, m); r.Status != StatusPass {
				t.Fatalf("files-map against expected map: %s: %s", r.Status, r.Detail)
			}

			// Every entry in the expected map must be exactly the file on
			// disk; a one-byte change to any of them must fail.
			for rel := range v.ExpectedFilesMap {
				p := filepath.Join(dir, filepath.FromSlash(rel))
				data, _ := os.ReadFile(p)
				if err := os.WriteFile(p, append(data, 'x'), 0o644); err != nil {
					t.Fatal(err)
				}
				if r := checkFilesMap(dir, m); r.Status != StatusFail {
					t.Errorf("touching %s must fail files-map, got %s", rel, r.Status)
				}
				if err := os.WriteFile(p, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			// Unsigned canonical form: add signature and timestamp blocks the
			// way a sealed manifest carries them; they must strip away.
			var obj map[string]interface{}
			if err := json.Unmarshal(v.Manifest, &obj); err != nil {
				t.Fatal(err)
			}
			obj["signatures"] = []interface{}{map[string]interface{}{"scheme": "ed25519", "signature": "AAAA", "publicKey": "PEM", "signedFields": "manifest.json"}}
			obj["timestamps"] = []interface{}{map[string]interface{}{"tsa": "X", "timestamp": "t", "tokenBase64": "AA=="}}
			sealed, _ := json.Marshal(obj)
			unsigned, err := manifest.StripSignatureFields(sealed)
			if err != nil {
				t.Fatal(err)
			}
			if string(unsigned) != v.ExpectedUnsignedCanonical {
				t.Errorf("unsigned canonical mismatch\n got: %s\nwant: %s", unsigned, v.ExpectedUnsignedCanonical)
			}
			sum := sha256.Sum256(unsigned)
			if got := hex.EncodeToString(sum[:]); got != v.ExpectedManifestHash {
				t.Errorf("manifest hash = %s, want %s", got, v.ExpectedManifestHash)
			}
		})
	}
}
