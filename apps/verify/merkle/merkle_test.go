package merkle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The vectors come from an independent Python oracle whose tree heads
// match the certificate-transparency project's published test roots.
// packages/chain/test/merkle.conformance.test.ts runs the same file.

type inclusionVector struct {
	Size     int      `json:"size"`
	Index    int      `json:"index"`
	LeafHash string   `json:"leafHash"`
	Path     []string `json:"path"`
	Root     string   `json:"root"`
}

type consistencyVector struct {
	First      int      `json:"first"`
	Second     int      `json:"second"`
	FirstRoot  string   `json:"firstRoot"`
	SecondRoot string   `json:"secondRoot"`
	Proof      []string `json:"proof"`
}

type vectors struct {
	LeafHashes []struct {
		Input    string `json:"input"`
		LeafHash string `json:"leafHash"`
	} `json:"leafHashes"`
	NodeHash struct {
		Left, Right, Expected string
	} `json:"nodeHash"`
	Roots []struct {
		Size int    `json:"size"`
		Root string `json:"root"`
	} `json:"roots"`
	InclusionProofs   []inclusionVector   `json:"inclusionProofs"`
	ConsistencyProofs []consistencyVector `json:"consistencyProofs"`
	ChainHashTree     struct {
		ChainHashes     []string `json:"chainHashes"`
		Root            string   `json:"root"`
		InclusionProofs []struct {
			Index int      `json:"index"`
			Path  []string `json:"path"`
		} `json:"inclusionProofs"`
		ConsistencyProofs []struct {
			First     int      `json:"first"`
			Proof     []string `json:"proof"`
			FirstRoot string   `json:"firstRoot"`
		} `json:"consistencyProofs"`
	} `json:"chainHashTree"`
	Negative []struct {
		Name string `json:"name"`
		inclusionVector
	} `json:"negative"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "conformance", "merkle-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors vectors `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return doc.Vectors
}

func b(t *testing.T, h string) []byte {
	t.Helper()
	out, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex %q: %v", h, err)
	}
	return out
}

func bs(t *testing.T, hs []string) [][]byte {
	out := make([][]byte, len(hs))
	for i, h := range hs {
		out[i] = b(t, h)
	}
	return out
}

func hexs(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, x := range bs {
		out[i] = hex.EncodeToString(x)
	}
	return out
}

func equalStrings(a, c []string) bool {
	if len(a) != len(c) {
		return false
	}
	for i := range a {
		if a[i] != c[i] {
			return false
		}
	}
	return true
}

func TestMerkleConformance(t *testing.T) {
	v := load(t)
	leaves := make([][]byte, len(v.LeafHashes))
	for i, lv := range v.LeafHashes {
		got := LeafHash(b(t, lv.Input))
		if hex.EncodeToString(got) != lv.LeafHash {
			t.Errorf("leaf %d: got %x", i, got)
		}
		leaves[i] = got
	}
	if got := NodeHash(b(t, v.NodeHash.Left), b(t, v.NodeHash.Right)); hex.EncodeToString(got) != v.NodeHash.Expected {
		t.Errorf("node hash: got %x", got)
	}
	for _, r := range v.Roots {
		if got := hex.EncodeToString(Root(leaves[:r.Size])); got != r.Root {
			t.Errorf("root size %d: got %s want %s", r.Size, got, r.Root)
		}
	}
	if v.Roots[8].Root != "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328" {
		t.Errorf("size-8 root is not the certificate-transparency test root")
	}
	for _, p := range v.InclusionProofs {
		got, err := InclusionProof(leaves[:p.Size], p.Index)
		if err != nil {
			t.Fatal(err)
		}
		if !equalStrings(hexs(got), p.Path) {
			t.Errorf("inclusion size %d index %d: path mismatch", p.Size, p.Index)
		}
		if !VerifyInclusion(b(t, p.LeafHash), p.Index, p.Size, bs(t, p.Path), b(t, p.Root)) {
			t.Errorf("inclusion size %d index %d: does not verify", p.Size, p.Index)
		}
	}
	for _, c := range v.ConsistencyProofs {
		got, err := ConsistencyProof(leaves[:c.Second], c.First)
		if err != nil {
			t.Fatal(err)
		}
		if !equalStrings(hexs(got), c.Proof) {
			t.Errorf("consistency %d->%d: proof mismatch", c.First, c.Second)
		}
		if !VerifyConsistency(c.First, c.Second, b(t, c.FirstRoot), b(t, c.SecondRoot), bs(t, c.Proof)) {
			t.Errorf("consistency %d->%d: does not verify", c.First, c.Second)
		}
	}
	for _, n := range v.Negative {
		if VerifyInclusion(b(t, n.LeafHash), n.Index, n.Size, bs(t, n.Path), b(t, n.Root)) {
			t.Errorf("%s: must not verify", n.Name)
		}
	}
}

func TestChainHashTreeVectors(t *testing.T) {
	v := load(t).ChainHashTree
	leaves := make([][]byte, len(v.ChainHashes))
	for i, h := range v.ChainHashes {
		leaves[i] = LeafHash(b(t, h))
	}
	root := Root(leaves)
	if hex.EncodeToString(root) != v.Root {
		t.Fatalf("root: got %x want %s", root, v.Root)
	}
	for _, p := range v.InclusionProofs {
		got, _ := InclusionProof(leaves, p.Index)
		if !equalStrings(hexs(got), p.Path) {
			t.Errorf("index %d: path mismatch", p.Index)
		}
		if !VerifyInclusion(leaves[p.Index], p.Index, len(leaves), bs(t, p.Path), root) {
			t.Errorf("index %d: does not verify", p.Index)
		}
	}
	for _, c := range v.ConsistencyProofs {
		got, _ := ConsistencyProof(leaves, c.First)
		if !equalStrings(hexs(got), c.Proof) {
			t.Errorf("consistency from %d: proof mismatch", c.First)
		}
		if !VerifyConsistency(c.First, len(leaves), b(t, c.FirstRoot), root, bs(t, c.Proof)) {
			t.Errorf("consistency from %d: does not verify", c.First)
		}
	}
}

func TestWrongRootRejected(t *testing.T) {
	v := load(t)
	leaves := make([][]byte, len(v.LeafHashes))
	for i, lv := range v.LeafHashes {
		leaves[i] = b(t, lv.LeafHash)
	}
	proof, _ := ConsistencyProof(leaves[:7], 3)
	wrong := Root(leaves)
	if VerifyConsistency(3, 7, Root(leaves[:3]), wrong, proof) {
		t.Error("consistency proof verified against an unrelated root")
	}
	path, _ := InclusionProof(leaves, 2)
	tampered := append([][]byte{}, path...)
	tampered[0] = bytes.Repeat([]byte{0xab}, HashSize)
	if VerifyInclusion(leaves[2], 2, 8, tampered, Root(leaves)) {
		t.Error("tampered audit path verified")
	}
}
