//go:build !linux

// Package probe on a platform without eBPF.
//
// macOS has no equivalent capture surface that DEPOSE can use: the kernel
// audit pipeline (Endpoint Security) needs a signed entitlement Apple
// grants per developer account, and openbsm auditing is deprecated and
// off by default. Rather than ship something that loads, records nothing,
// and lets a bundle look kernel-witnessed when it is not, the collector
// refuses to start and says so. macOS captures through the agent hook
// only. See docs/capture-coverage.md.
package probe

import "fmt"

// Probe is never constructed on this platform.
type Probe struct{}

// Open always fails on a platform with no eBPF.
//
// @returns ErrNotSupported, wrapped with the platform name.
func Open() (*Probe, error) {
	return nil, fmt.Errorf("%w", ErrNotSupported)
}

// Read is unreachable; Open never returns a probe here.
func (p *Probe) Read() (Event, error) { return Event{}, ErrNotSupported }

// Close is unreachable; Open never returns a probe here.
func (p *Probe) Close() error { return nil }
