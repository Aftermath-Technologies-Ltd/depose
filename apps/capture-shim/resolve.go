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

		// Must be executable
		if info.IsDir() {
			continue
		}

		// Check if executable (simplified: file exists and is not dir)
		candidates = append(candidates, candidate)
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("real binary %q not found on PATH (after excluding shim dir %s)", name, shimDir)
	}

	return candidates[0], nil
}

// isSelf checks if the given binary path is the shim itself.
func isSelf(path string) bool {
	selfPath, _ := filepath.Abs(os.Args[0])
	absPath, _ := filepath.Abs(path)
	return selfPath == absPath || strings.HasPrefix(absPath, filepath.Dir(selfPath)+string(filepath.Separator)+"capture-shim")
}
