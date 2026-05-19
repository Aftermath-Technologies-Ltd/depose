// apps/capture-shim/main.go
//
// capture-shim: A Go binary that, when invoked under the name of a
// destructive binary on PATH, writes a capture record then execs
// through to the real binary with full stdio/signal/exit-code passthrough.
//
// BUILD_PLAN.md §6 (Phase 3): "single binary symlinked under multiple names"
//
// Behavior:
//   1. Determine real binary by walking PATH and skipping the shim directory.
//   2. Capture argv, env subset, cwd, ppid tree, stdin tee (if < 1 MB).
//   3. Write a ShellCommandPrePayload JSON to $DEPOSE_CAPTURE_DIR/<ulid>.json.
//   4. syscall.Exec to the real binary.
//   5. If stdin was tee'd, stream the tee back as stdin to the child.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// Determine the name under which we were invoked (argv0)
	invokedAs := filepath.Base(os.Args[0])

	// Find the real binary by walking PATH, skipping our own directory
	realBinary, err := findRealBinary(invokedAs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "depose-shim: ERROR: %v\n", err)
		os.Exit(127)
	}

	// Self-loop protection: if the real binary is ourselves, abort
	if isSelf(realBinary) {
		fmt.Fprintf(os.Stderr, "depose-shim: FATAL: resolved real binary is the shim itself (%s). Check PATH ordering.\n", realBinary)
		os.Exit(126)
	}

	// Capture pre-execution record
	capturePath, err := writeCaptureRecord(invokedAs, os.Args[1:])
	if err != nil {
		// Log but do not block execution
		fmt.Fprintf(os.Stderr, "depose-shim: capture error: %v\n", err)
	}

	if capturePath != "" {
		fmt.Fprintf(os.Stderr, "depose-shim: capture %s\n", filepath.Base(capturePath))
	}

	// Exec through to the real binary with full passthrough
	execThrough(realBinary, os.Args)
}
