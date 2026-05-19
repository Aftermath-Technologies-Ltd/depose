// Package canonical implements RFC 8785 JSON Canonicalization Scheme
// (JCS) for the subset of JSON that appears in DEPOSE bundles.
//
// JCS guarantees byte-for-byte determinism between language
// implementations. The TypeScript producer and this Go verifier
// must agree on the exact bytes to sign/verify.
//
// See docs/canonical-json.md for the spec.
package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Marshal returns the canonical JSON bytes for the given value.
// The input must be a value previously decoded via encoding/json
// (i.e. comprised of map[string]any, []any, string, float64, bool,
// or nil). Custom struct types should be converted via
// json.Marshal/Unmarshal first.
func Marshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalRaw re-canonicalizes already-JSON bytes. This is the entry
// point the verifier uses to canonicalize a manifest read from disk.
func MarshalRaw(jsonBytes []byte) ([]byte, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	return Marshal(v)
}

func writeValue(buf *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeString(buf, x)
	case json.Number:
		return writeNumberRaw(buf, x.String())
	case float64:
		// Path used when the caller hand-builds values without
		// UseNumber. Reuse the standard encoder for the number form
		// — it follows ECMA-262 ToString(Number) for finite values.
		bts, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(bts)
		return nil
	case int, int64, uint64:
		bts, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(bts)
		return nil
	case []interface{}:
		buf.WriteByte('[')
		for i, elt := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, elt); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// JCS sort: UTF-16 code unit order. For ASCII keys this is
		// the same as byte order. For non-ASCII keys we sort by
		// UTF-16 code units (see sortKeysUTF16 below).
		sortKeysUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonical: unsupported value type %T", v)
	}
}

// writeNumberRaw writes a numeric value that was decoded as
// json.Number. We accept the lexical form the decoder produced —
// JCS-compliant producers (TypeScript JSON.stringify) emit the
// shortest unambiguous form, and re-parsing through json.Number
// preserves those bytes.
//
// JCS §3.2.2.2 collapses negative zero to "0"; Go's encoder
// preserves the sign for json.Number("-0"), so we normalize here.
func writeNumberRaw(buf *bytes.Buffer, s string) error {
	if s == "-0" {
		buf.WriteByte('0')
		return nil
	}
	buf.WriteString(s)
	return nil
}

// writeString emits a JSON string in JCS form: minimum escape set,
// no HTML escaping, literal UTF-8 for non-ASCII characters.
func writeString(buf *bytes.Buffer, s string) error {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, c)
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// sortKeysUTF16 sorts a slice of strings by UTF-16 code unit order.
// JCS §3.2.3 requires this. For ASCII-only keys it's identical to
// byte order; for keys containing surrogate-pair code points the
// behavior differs from plain byte sort.
func sortKeysUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})
}

func lessUTF16(a, b string) bool {
	ai, bi := 0, 0
	for ai < len(a) && bi < len(b) {
		ar, asz := nextUTF16Unit(a[ai:])
		br, bsz := nextUTF16Unit(b[bi:])
		if ar != br {
			return ar < br
		}
		ai += asz
		bi += bsz
	}
	return len(a) < len(b)
}

// nextUTF16Unit returns the next UTF-16 code unit from the UTF-8
// prefix of s, plus the number of UTF-8 bytes consumed.
func nextUTF16Unit(s string) (uint32, int) {
	if len(s) == 0 {
		return 0, 0
	}
	b0 := s[0]
	switch {
	case b0 < 0x80:
		return uint32(b0), 1
	case b0 < 0xC0:
		return uint32(b0), 1 // invalid leading byte; degrade
	case b0 < 0xE0 && len(s) >= 2:
		r := (uint32(b0&0x1F) << 6) | uint32(s[1]&0x3F)
		return r, 2
	case b0 < 0xF0 && len(s) >= 3:
		r := (uint32(b0&0x0F) << 12) | (uint32(s[1]&0x3F) << 6) | uint32(s[2]&0x3F)
		return r, 3
	case len(s) >= 4:
		r := (uint32(b0&0x07) << 18) | (uint32(s[1]&0x3F) << 12) | (uint32(s[2]&0x3F) << 6) | uint32(s[3]&0x3F)
		// Encode supplementary plane char as high surrogate; the
		// low surrogate sorts after, which JCS handles by comparing
		// surrogate pairs as separate code units.
		if r >= 0x10000 {
			r -= 0x10000
			high := 0xD800 + (r >> 10)
			return high, 4
		}
		return r, 4
	}
	return uint32(b0), 1
}
