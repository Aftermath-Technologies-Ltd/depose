// Package merkle implements the RFC 6962 Merkle tree the producer builds
// over per-event chain hashes, plus inclusion and consistency proof
// verification. It mirrors packages/chain/src/merkle.ts byte for byte;
// tests/conformance/merkle-vectors.json pins both.
//
//	leaf(i)   = SHA-256( 0x00 || chainHash[i] )
//	node(l,r) = SHA-256( 0x01 || l || r )
//	MTH([])   = SHA-256( "" )
//	MTH(D[n]) = node( MTH(D[0:k]), MTH(D[k:n]) ), k = largest power of two < n
package merkle

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// HashSize is the byte length of every hash in the tree.
const HashSize = sha256.Size

// LeafHash hashes a leaf input with the 0x00 prefix.
func LeafHash(input []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(input)
	return h.Sum(nil)
}

// NodeHash hashes two children with the 0x01 prefix.
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func splitPoint(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Root returns MTH over already-hashed leaves; SHA-256("") when empty.
func Root(leaves [][]byte) []byte {
	return subtreeRoot(leaves, 0, len(leaves))
}

func subtreeRoot(leaves [][]byte, start, end int) []byte {
	n := end - start
	if n == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	if n == 1 {
		return leaves[start]
	}
	k := splitPoint(n)
	return NodeHash(subtreeRoot(leaves, start, start+k), subtreeRoot(leaves, start+k, end))
}

// InclusionProof returns the RFC 6962 audit path for leaf index in the tree.
func InclusionProof(leaves [][]byte, index int) ([][]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("inclusion proof index %d is out of range for %d leaves", index, len(leaves))
	}
	return auditPath(leaves, index, 0, len(leaves)), nil
}

func auditPath(leaves [][]byte, index, start, end int) [][]byte {
	n := end - start
	if n <= 1 {
		return nil
	}
	k := splitPoint(n)
	if index < start+k {
		return append(auditPath(leaves, index, start, start+k), subtreeRoot(leaves, start+k, end))
	}
	return append(auditPath(leaves, index, start+k, end), subtreeRoot(leaves, start, start+k))
}

// RootFromInclusionProof recomputes the root a leaf and its audit path
// lead to (RFC 6962 §2.1.1). Path length must match the tree shape.
func RootFromInclusionProof(leaf []byte, index, size int, proof [][]byte) ([]byte, error) {
	if index < 0 || index >= size {
		return nil, fmt.Errorf("leaf index %d is out of range for a tree of %d", index, size)
	}
	fn, sn := index, size-1
	r := leaf
	used := 0
	for sn > 0 {
		if used >= len(proof) {
			return nil, fmt.Errorf("audit path is too short: %d hash(es) for index %d of %d", len(proof), index, size)
		}
		p := proof[used]
		used++
		if fn%2 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if used != len(proof) {
		return nil, fmt.Errorf("audit path is too long: %d hash(es), %d consumed", len(proof), used)
	}
	return r, nil
}

// VerifyInclusion reports whether the audit path proves leaf at index in
// a tree of size with the given root.
func VerifyInclusion(leaf []byte, index, size int, proof [][]byte, root []byte) bool {
	got, err := RootFromInclusionProof(leaf, index, size, proof)
	return err == nil && bytes.Equal(got, root)
}

// ConsistencyProof returns the RFC 6962 proof that the first m leaves
// form a prefix of the tree over all leaves.
func ConsistencyProof(leaves [][]byte, m int) ([][]byte, error) {
	n := len(leaves)
	if m <= 0 || m > n {
		return nil, fmt.Errorf("consistency proof needs 0 < m <= n; got m=%d, n=%d", m, n)
	}
	if m == n {
		return nil, nil
	}
	return subProof(leaves, m, 0, n, true), nil
}

func subProof(leaves [][]byte, m, start, end int, isRoot bool) [][]byte {
	n := end - start
	if m == n {
		if isRoot {
			return nil
		}
		return [][]byte{subtreeRoot(leaves, start, end)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subProof(leaves, m, start, start+k, isRoot), subtreeRoot(leaves, start+k, end))
	}
	return append(subProof(leaves, m-k, start+k, end, false), subtreeRoot(leaves, start, start+k))
}

// VerifyConsistency checks a consistency proof between tree sizes m and n
// per RFC 9162 §2.1.4.2.
func VerifyConsistency(m, n int, rootM, rootN []byte, proof [][]byte) bool {
	if m <= 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && bytes.Equal(rootM, rootN)
	}
	if len(proof) == 0 {
		return false
	}
	fn, sn := m-1, n-1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}
	idx := 0
	var fr, sr []byte
	if fn == 0 {
		fr, sr = rootM, rootM
	} else {
		fr, sr = proof[0], proof[0]
		idx = 1
	}
	for sn > 0 {
		if idx >= len(proof) {
			return false
		}
		c := proof[idx]
		idx++
		if fn%2 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return idx == len(proof) && bytes.Equal(fr, rootM) && bytes.Equal(sr, rootN)
}
