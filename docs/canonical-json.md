# DEPOSE canonical JSON

DEPOSE serializes JSON deterministically so that the same logical
value always produces the same bytes — across implementations and
across machines. This is what lets a signature created in TypeScript
verify in Go (and vice versa).

The canonical form is **RFC 8785 JSON Canonicalization Scheme (JCS)**.
We adopt JCS as-is for the subset of JSON that appears in DEPOSE
bundles. Conformance vectors live in
[`tests/conformance/canonical-json-vectors.json`](../tests/conformance/canonical-json-vectors.json).
A CI job (`conformance-canonical-json`) runs the vectors against both
the TypeScript and Go implementations on every PR — any divergence
blocks the merge.

## Where canonical JSON is used

- **`manifest.json`** is canonical JSON. The Ed25519 signature is
  computed over the canonical bytes of the manifest with
  `signatures` and `timestamps` stripped (the "unsigned form").
- **`events.jsonl`** is one canonical JSON object per line.
- **`payloadHash`** and **`chainHash`** are SHA-256 over canonical
  JSON of the relevant subtree.

If a value is not canonical, it cannot be hashed or signed
reproducibly. Treat any code path that hashes or signs as a strict
JCS consumer.

## The rules (RFC 8785 §3 summary)

1. **Object keys are sorted** by UTF-16 code unit order. For ASCII
   keys this matches a plain byte sort.
2. **No whitespace** between tokens. `{"a":1,"b":2}`, never
   `{ "a" : 1 , "b" : 2 }`.
3. **String escapes** use the JSON minimum escape set:
   `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00XX` for the
   remaining C0 control characters (U+0000..U+001F). Any other
   character — including `<`, `>`, `&`, `/`, and non-ASCII Unicode
   — is emitted **literally as UTF-8**, never escaped.
4. **Numbers** are serialized via the ECMA-262 `ToString(Number)`
   algorithm: integers in `[-2^53, 2^53]` print without a decimal
   point or exponent; other values use the shortest unambiguous
   form. NaN and ±Infinity are not permitted.
5. **Arrays** preserve their input order.
6. **`null`**, **`true`**, **`false`** are lowercase, no
   alternatives.

## Implementation notes per language

### TypeScript (`packages/core/src/events/canonical-json.ts`)

Node's `JSON.stringify(value, null, 0)` already produces the
right number serialization, the JSON minimum escape set, and
literal UTF-8 for non-ASCII printable characters. We preprocess
the value with `sortKeys` (recursive deep key sort) before calling
`JSON.stringify`.

`JSON.stringify` **does not** HTML-escape `<`, `>`, `&` — it leaves
them literal. This matches JCS.

### Go (`apps/verify/canonical/jcs.go`)

Go's default `encoding/json` writer **does** HTML-escape `<`, `>`,
and `&` (to `<`, `>`, `&`). That is the historical
hedge against `<script>` injection in browser JSON contexts; it is
not what JCS specifies. We use `json.Encoder` with
`SetEscapeHTML(false)` and re-sort map keys by UTF-16 code units
when serializing.

The verifier's `StripSignatureFields` re-marshals the manifest with
`signatures` and `timestamps` cleared. It uses the canonical writer
so the bytes match TypeScript's signed form byte-for-byte.

## What this scheme does not cover

JCS does not say anything about `application/jose` JWS or `JOSE`
serialization. We are not using either. The signature payload is
the raw canonical bytes of the unsigned manifest, hashed with
SHA-256, signed with Ed25519. See `docs/bundle-format.md` §7.1 for
the signing procedure.
