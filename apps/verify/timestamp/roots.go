// Embedded trust roots for the TSAs DEPOSE uses by default.
//
// Both are embedded rather than left to the host, because the whole
// claim of an off-host verifier is that the same bundle gets the same
// answer everywhere. It does not, if the answer depends on the
// recipient's trust store: a DigiCert-anchored bundle verified on Linux
// and failed on macOS, where Go's SystemCertPool does not surface the
// root that the chain needs. That is a bundle whose validity depends on
// who is looking at it, which is the one property this tool cannot have.
//
// The system pool is still added underneath, so a bundle anchored to a
// TSA DEPOSE does not ship a root for still verifies wherever the host
// trusts that CA.
//
// Production verifier binaries embed only these roots. The
// "test_roots.go" build-tagged file may register additional roots
// for fixtures, never built into a release binary.
package timestamp

import (
	_ "embed"
)

// FreeTSA is a self-signed CA and is in no OS trust store at all.
//
//go:embed roots/freetsa-ca.pem
var FreeTSACARootPEM []byte

// DigiCertTrustedRootG4PEM is the root the DigiCert timestamping chain
// terminates at (DigiCert Trusted Root G4, valid to 2038-01-15). It is
// publicly trusted, so this pins rather than introduces trust: the
// checked-in copy is byte-identical to both Mozilla's CA bundle and
// DigiCert's own published copy, SHA-256
// 552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988.
// timestamp_roots_test.go re-derives that digest so a swapped file is a
// failing test rather than a silent change of trust anchor.
//
//go:embed roots/digicert-trusted-root-g4.pem
var DigiCertTrustedRootG4PEM []byte
