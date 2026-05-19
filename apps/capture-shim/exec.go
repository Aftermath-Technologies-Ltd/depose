// apps/capture-shim/exec.go
//
// Transparent exec with stdio passthrough.
// Uses syscall.Exec on Unix to replace the current process.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// execThrough replaces the current process with the real binary.
// On Unix, uses syscall.Exec for transparent passthrough (no child process).
// Falls back to exec + Wait on non-Unix or if Exec fails.
func execThrough(realBinary string, argv []string) {
	// Tee stdin if small enough, then exec
	stdinReader, cleanup := teeStdin()
	defer cleanup()

	// Try syscall.Exec first (Unix only, transparent)
	if syscall.Exec(realBinary, argv, os.Environ()) != nil {
		// Fallback: run as child process (preserves exit code and signals)
		runAsChild(realBinary, argv, stdinReader)
	}
	// syscall.Exec never returns on success
}

// runAsChild runs the real binary as a child process.
// Preserves exit code and propagates signals.
func runAsChild(realBinary string, argv []string, stdinReader *os.File) {
	cmd := exec.Command(realBinary, argv[1:]...)
	cmd.Stdin = stdinReader
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	// Start the child
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "depose-shim: exec error: %v\n", err)
		os.Exit(126)
	}

	// Propagate signals to the child
	go propagateSignals(cmd.Process)

	// Wait for child to finish
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "depose-shim: wait error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
