// Embedded trust roots for the TSAs DEPOSE uses.
//
// FreeTSA is a self-signed CA, so its root is not in the system
// trust store. We ship it embedded in the verifier binary. DigiCert
// and Sectigo TSAs chain to publicly trusted CAs that the OS already
// knows about, so for those we add the system pool too.
//
// Production verifier binaries embed only these roots. The
// "test_roots.go" build-tagged file may register additional roots
// for fixtures — never built into a release binary.
package timestamp

import (
	_ "embed"
)

//go:embed roots/freetsa-ca.pem
var FreeTSACARootPEM []byte
