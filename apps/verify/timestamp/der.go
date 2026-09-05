// Package timestamp, strict DER well-formedness check.
//
// The verifier hands TSR bytes to digitorus/timestamp and digitorus/pkcs7,
// whose BER-to-DER converter indexes past the end of a truncated input
// and panics (found by FuzzParseTSR on the two-byte input 0x3f 0x30). A
// recipient must never see the verifier crash on attacker-chosen bytes,
// and a crash is not a verdict. Every token is therefore walked here
// first: each tag-length-value must be complete, use definite length,
// and fit inside its enclosing element, with no trailing bytes. RFC 3161
// tokens are DER by specification, so nothing legitimate is rejected;
// the producer-side parser (packages/chain/src/asn1-der.ts) applies the
// same rules.
package timestamp

import "fmt"

const maxDERDepth = 64

// checkDER returns an error unless b is one complete, well-formed DER
// element with no trailing bytes.
func checkDER(b []byte) error {
	next, err := walkDER(b, 0, len(b), 0)
	if err != nil {
		return err
	}
	if next != len(b) {
		return fmt.Errorf("DER: %d trailing byte(s) after the outer element", len(b)-next)
	}
	return nil
}

// walkDER validates the element starting at off, which must end at or
// before end, and returns the offset just past it. Constructed elements
// are walked recursively.
func walkDER(b []byte, off, end, depth int) (int, error) {
	if depth > maxDERDepth {
		return 0, fmt.Errorf("DER: nesting deeper than %d at offset %d", maxDERDepth, off)
	}
	if off >= end {
		return 0, fmt.Errorf("DER: element expected at offset %d but the enclosing element ends at %d", off, end)
	}
	tag := b[off]
	pos := off + 1
	if tag&0x1f == 0x1f {
		// High tag number: continuation bytes with the top bit set.
		for {
			if pos >= end {
				return 0, fmt.Errorf("DER: truncated high tag number at offset %d", off)
			}
			c := b[pos]
			pos++
			if c&0x80 == 0 {
				break
			}
			if pos-off > 6 {
				return 0, fmt.Errorf("DER: tag number too long at offset %d", off)
			}
		}
	}
	if pos >= end {
		return 0, fmt.Errorf("DER: missing length at offset %d", off)
	}
	lenByte := b[pos]
	pos++
	var length int
	switch {
	case lenByte < 0x80:
		length = int(lenByte)
	case lenByte == 0x80:
		return 0, fmt.Errorf("DER: indefinite length at offset %d is not allowed", off)
	default:
		n := int(lenByte & 0x7f)
		if n > 4 {
			return 0, fmt.Errorf("DER: length of %d bytes at offset %d exceeds the 4-byte limit", n, off)
		}
		if pos+n > end {
			return 0, fmt.Errorf("DER: truncated length at offset %d", off)
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(b[pos+i])
		}
		pos += n
		if length < 0x80 && n == 1 || n > 1 && length < 1<<(8*(n-1)) {
			return 0, fmt.Errorf("DER: non-minimal length encoding at offset %d", off)
		}
	}
	if length > end-pos {
		return 0, fmt.Errorf("DER: element at offset %d claims %d bytes but only %d remain", off, length, end-pos)
	}
	valueEnd := pos + length
	if tag&0x20 != 0 {
		cur := pos
		for cur < valueEnd {
			next, err := walkDER(b, cur, valueEnd, depth+1)
			if err != nil {
				return 0, err
			}
			cur = next
		}
	}
	return valueEnd, nil
}
