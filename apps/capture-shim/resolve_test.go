// apps/capture-shim/resolve_test.go
//
// The shim is symlinked in front of rm, terraform, kubectl, aws, and psql
// on the user's PATH and had no tests at all. Resolution bugs here either
// break destructive commands outright or silently exec the wrong binary,
// so the resolution rules are pinned.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withArgv0 points os.Args[0] at path for the duration of the test.
func withArgv0(t *testing.T, path string) {
	t.Helper()
	original := os.Args[0]
	os.Args[0] = path
	t.Cleanup(func() { os.Args[0] = original })
}

// writeExecutable creates an executable file and returns its path.
func writeExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestFindRealBinaryResolvesFromPath(t *testing.T) {
	shimDir := t.TempDir()
	realDir := t.TempDir()
	want := writeExecutable(t, realDir, "terraform")

	withArgv0(t, filepath.Join(shimDir, "terraform"))
	t.Setenv("PATH", strings.Join([]string{shimDir, realDir}, string(os.PathListSeparator)))

	got, err := findRealBinary("terraform")
	if err != nil {
		t.Fatalf("findRealBinary: %v", err)
	}
	if got != want {
		t.Errorf("resolved %q, want %q", got, want)
	}
}

func TestFindRealBinarySkipsItsOwnDirectory(t *testing.T) {
	shimDir := t.TempDir()
	realDir := t.TempDir()

	// A binary of the same name sits in the shim's own directory. Choosing
	// it would exec the shim again and loop forever.
	writeExecutable(t, shimDir, "rm")
	want := writeExecutable(t, realDir, "rm")

	withArgv0(t, filepath.Join(shimDir, "rm"))
	t.Setenv("PATH", strings.Join([]string{shimDir, realDir}, string(os.PathListSeparator)))

	got, err := findRealBinary("rm")
	if err != nil {
		t.Fatalf("findRealBinary: %v", err)
	}
	if got != want {
		t.Errorf("resolved %q, want %q (must skip the shim dir)", got, want)
	}
}

func TestFindRealBinaryIgnoresDirectoriesWithMatchingNames(t *testing.T) {
	shimDir := t.TempDir()
	decoyDir := t.TempDir()
	realDir := t.TempDir()

	if err := os.Mkdir(filepath.Join(decoyDir, "kubectl"), 0755); err != nil {
		t.Fatalf("mkdir decoy: %v", err)
	}
	want := writeExecutable(t, realDir, "kubectl")

	withArgv0(t, filepath.Join(shimDir, "kubectl"))
	t.Setenv("PATH", strings.Join([]string{shimDir, decoyDir, realDir}, string(os.PathListSeparator)))

	got, err := findRealBinary("kubectl")
	if err != nil {
		t.Fatalf("findRealBinary: %v", err)
	}
	if got != want {
		t.Errorf("resolved %q, want %q (a directory is not a binary)", got, want)
	}
}

func TestFindRealBinarySkipsNonExecutableFiles(t *testing.T) {
	shimDir := t.TempDir()
	decoyDir := t.TempDir()
	realDir := t.TempDir()

	// A readable but non-executable file of the same name. Selecting it
	// makes the exec fail and takes the real command down with it.
	decoy := filepath.Join(decoyDir, "psql")
	if err := os.WriteFile(decoy, []byte("not executable"), 0644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	want := writeExecutable(t, realDir, "psql")

	withArgv0(t, filepath.Join(shimDir, "psql"))
	t.Setenv("PATH", strings.Join([]string{shimDir, decoyDir, realDir}, string(os.PathListSeparator)))

	got, err := findRealBinary("psql")
	if err != nil {
		t.Fatalf("findRealBinary: %v", err)
	}
	if got != want {
		t.Errorf("resolved %q, want %q (non-executable files are not binaries)", got, want)
	}
}

func TestFindRealBinaryErrorsWhenNothingOnPath(t *testing.T) {
	shimDir := t.TempDir()
	withArgv0(t, filepath.Join(shimDir, "terraform"))
	t.Setenv("PATH", shimDir)

	if _, err := findRealBinary("terraform"); err == nil {
		t.Fatal("expected an error when the real binary is absent, got nil")
	}
}

func TestFindRealBinaryErrorsWhenPathUnset(t *testing.T) {
	withArgv0(t, filepath.Join(t.TempDir(), "aws"))
	t.Setenv("PATH", "")

	if _, err := findRealBinary("aws"); err == nil {
		t.Fatal("expected an error when PATH is unset, got nil")
	}
}

func TestIsSelfMatchesOwnPath(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "terraform")
	withArgv0(t, self)

	if !isSelf(self) {
		t.Error("isSelf must recognize our own argv[0]")
	}
}

func TestIsSelfMatchesAnyShimBinaryName(t *testing.T) {
	withArgv0(t, filepath.Join(t.TempDir(), "terraform"))

	// Any executable named depose-shim is the shim, wherever it lives.
	// Exec'ing it as the "real" binary re-enters the shim with no progress.
	if !isSelf(filepath.Join(t.TempDir(), "depose-shim")) {
		t.Error("isSelf must recognize the shim by basename, in any directory")
	}
}

func TestIsSelfAcceptsRealBinaries(t *testing.T) {
	withArgv0(t, filepath.Join(t.TempDir(), "terraform"))

	if isSelf("/usr/bin/terraform") {
		t.Error("isSelf must not flag an unrelated real binary")
	}
}
