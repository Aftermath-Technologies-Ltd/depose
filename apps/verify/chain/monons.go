// Package chain, the monoNs wire form.
//
// Schema 3 writes monoNs as a decimal string and schema 2 wrote a JSON
// number. The difference matters: a JSON number loses precision past
// 2^53, so two events a nanosecond apart could hash the same metadata.
// The token is kept raw through parsing and re-canonicalized in exactly
// the form the producer hashed.
package chain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// monoNsPattern is the schema 3 wire form: a non-negative decimal
// integer string with no leading zeros.
var monoNsPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// MonoNsValue decodes a monoNs token to int64 and reports whether it was
// a string. A string must match monoNsPattern and fit int64; a number
// must be a non-negative integer.
func MonoNsValue(raw json.RawMessage) (value int64, isString bool, err error) {
	if len(raw) == 0 {
		return 0, false, fmt.Errorf("monoNs is missing")
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, true, fmt.Errorf("monoNs is not a JSON string: %w", err)
		}
		if !monoNsPattern.MatchString(s) {
			return 0, true, fmt.Errorf("monoNs %q is not a non-negative decimal integer", s)
		}
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, true, fmt.Errorf("monoNs %q does not fit int64", s)
		}
		return v, true, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false, fmt.Errorf("monoNs is neither a string nor a number: %w", err)
	}
	v, err := n.Int64()
	if err != nil || v < 0 {
		return 0, false, fmt.Errorf("monoNs %s is not a non-negative integer", n.String())
	}
	return v, false, nil
}
