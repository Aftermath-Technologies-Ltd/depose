//go:build !linux

package probe

import (
	"errors"
	"strings"
	"testing"
)

// The stub is the reason a macOS bundle can say kernel witnessing was
// requested and unavailable instead of looking like a session where
// nothing ran outside the hook. Nobody runs this path in development,
// so without a test asserting what it does, it only has to keep
// compiling to look healthy.

func TestOpenRefusesOnAPlatformWithoutEbpf(t *testing.T) {
	probe, err := Open()
	if err == nil {
		t.Fatal("Open must fail where there is no eBPF; a probe that reads nothing would let a bundle look kernel-witnessed")
	}
	if probe != nil {
		t.Error("Open must not return a probe alongside its error")
	}
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("error must wrap ErrNotSupported so main can record the ebpf-unsupported phase; got %v", err)
	}
}

func TestNotSupportedErrorSaysWhatStillGetsCaptured(t *testing.T) {
	// The message reaches the operator through a capture_failed record,
	// so it has to say what failed and what the bundle still contains.
	msg := ErrNotSupported.Error()
	for _, want := range []string{"Linux eBPF", "agent hook"} {
		if !strings.Contains(msg, want) {
			t.Errorf("ErrNotSupported message %q does not mention %q", msg, want)
		}
	}
}
