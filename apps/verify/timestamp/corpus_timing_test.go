package timestamp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFuzzCorpusIsFast replays every saved fuzz corpus entry (the
// checked-in crashers under testdata/fuzz and, when present, the local
// cache from a -fuzz run) and fails if any single input takes longer
// than a second. A DER parser must be linear in input size; an input
// that stalls the verifier is a denial-of-service against the recipient.
func TestFuzzCorpusIsFast(t *testing.T) {
	var dirs []string
	dirs = append(dirs, filepath.Join("testdata", "fuzz", "FuzzParseTSR"))
	if cache := os.Getenv("DEPOSE_FUZZ_CACHE"); cache != "" {
		dirs = append(dirs, cache)
	}
	expected := sha256.Sum256([]byte("fuzz"))
	expectedHex := hex.EncodeToString(expected[:])
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			data := decodeCorpusEntry(t, string(raw))
			start := time.Now()
			_, _ = parseTSR(data)
			VerifyToken(Token{TSA: "corpus", TokenBase64: base64.StdEncoding.EncodeToString(data)}, expectedHex)
			if d := time.Since(start); d > time.Second {
				t.Errorf("%s/%s: %d bytes took %s", dir, e.Name(), len(data), d)
			}
		}
	}
}

// decodeCorpusEntry parses the "go test fuzz v1" corpus file format,
// which holds one []byte literal.
func decodeCorpusEntry(t *testing.T, text string) []byte {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) < 2 || lines[0] != "go test fuzz v1" {
		t.Fatalf("unexpected corpus format")
	}
	lit := strings.TrimSpace(lines[1])
	lit = strings.TrimPrefix(lit, "[]byte(")
	lit = strings.TrimSuffix(lit, ")")
	s, err := strconv.Unquote(lit)
	if err != nil {
		t.Fatalf("decode corpus literal: %v", err)
	}
	return []byte(s)
}
