package canonical

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vector struct {
	Name     string      `json:"name"`
	Input    interface{} `json:"input"`
	Expected string      `json:"expected"`
}

type vectorFile struct {
	Description string   `json:"description"`
	Vectors     []vector `json:"vectors"`
}

// TestConformance runs the shared JCS vector suite against the Go
// canonicalizer. Same vectors run in TypeScript, any divergence
// breaks cross-language signature verification. See
// docs/canonical-json.md.
func TestConformance(t *testing.T) {
	path := filepath.Join("..", "..", "..", "tests", "conformance", "canonical-json-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}

	// We re-decode each vector's `input` with UseNumber to preserve
	// numeric lexical form, JCS demands the producer's choice of
	// integer vs decimal representation.
	var doc vectorFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vector file: %v", err)
	}

	for _, v := range doc.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			// Re-decode the input through UseNumber by serializing
			// the already-decoded value back to JSON, then decoding
			// with UseNumber so json.Number is preserved.
			interim, err := json.Marshal(v.Input)
			if err != nil {
				t.Fatalf("re-encode input: %v", err)
			}
			got, err := MarshalRaw(interim)
			if err != nil {
				t.Fatalf("MarshalRaw: %v", err)
			}
			if string(got) != v.Expected {
				t.Errorf("canonical form mismatch\nvector:   %s\nwant: %q\ngot:  %q", v.Name, v.Expected, string(got))
			}
		})
	}
}
