// apps/capture-shim/resolve.go
//
// Binary resolution: find the real binary by walking PATH,
// skipping the shim\'s own directory.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// findRealBinary walks PATH to find the real binary named `name`,
// skipping the shim\'s own directory.
func findRealBinary(name string) (string, error) {
	shimDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("PATH is not set")
	}

	dirs := filepath.SplitList(pathEnv)
	candidates := []string{}

	for _, dir := range dirs {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			continue
		}

		// Skip the shim\'s own directory
		if absDir == shimDir {
			continue
		}

		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}

		if info.IsDir() {
			continue
		}

		// Must actually be executable. This used to accept any regular
		// file, so a non-executable file named `terraform` sitting earlier
		// on PATH would shadow the real binary and the exec would fail,
		// taking the user's command down with it.
		if info.Mode().Perm()&0111 == 0 {
			continue
		}

		candidates = append(candidates, candidate)
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("real binary %q not found on PATH (after excluding shim dir %s)", name, shimDir)
	}

	return candidates[0], nil
}

// isSelf checks if the given binary path is the shim itself.
//
// Two checks:
//  1. Same absolute path as our argv[0]. Catches the obvious self-loop
//     where PATH ordering or a symlink resolves the "real" binary back
//     to the shim that's currently executing.
//  2. The candidate's basename is "depose-shim". Any executable named
//     depose-shim on PATH is the shim, regardless of which directory
//     it's in: invoking that as the "real" binary would re-enter the
//     shim with no progress. The earlier code matched a literal
//     "capture-shim" suffix that does not correspond to any binary
//     the project ships; this check uses the actual shim binary name
//     instead.
func isSelf(path string) bool {
	selfPath, _ := filepath.Abs(os.Args[0])
	absPath, _ := filepath.Abs(path)
	if selfPath == absPath {
		return true
	}
	return strings.EqualFold(filepath.Base(absPath), "depose-shim")
}
