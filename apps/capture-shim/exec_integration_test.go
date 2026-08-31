// apps/capture-shim/exec_integration_test.go
//
// End-to-end passthrough: build the shim, symlink it under a destructive
// binary's name, and run it against a stand-in "real" binary.
//
// execThrough calls syscall.Exec, which replaces the process, so it cannot
// be exercised in-process. These tests run the real binary and assert the
// contract the shim promises: argv, stdout, stdin, and exit code reach the
// real command unchanged, and a capture record lands on disk. A shim that
// mangles argv or swallows an exit code silently corrupts every command it
// sits in front of, including rm and terraform.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildShim compiles the shim once per test binary run.
func buildShim(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "depose-shim")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return binary
}

// shimEnv sets up a shim dir (symlinked as `name`), a real-binary dir
// holding `script`, and a capture dir. It returns the shim symlink path,
// the capture dir, and the PATH to run under.
func shimEnv(t *testing.T, name, script string) (shimPath, captureDir, path string) {
	t.Helper()
	shim := buildShim(t)

	shimDir := t.TempDir()
	realDir := t.TempDir()
	captureDir = filepath.Join(t.TempDir(), "captures")

	shimPath = filepath.Join(shimDir, name)
	if err := os.Symlink(shim, shimPath); err != nil {
		t.Fatalf("symlink shim as %s: %v", name, err)
	}

	realPath := filepath.Join(realDir, name)
	if err := os.WriteFile(realPath, []byte(script), 0755); err != nil {
		t.Fatalf("write stand-in binary: %v", err)
	}

	// The shim dir and the stand-in dir come first so they win resolution,
	// but the inherited PATH stays on the end: the stand-in binaries are
	// /bin/sh scripts and need the system tools their bodies call.
	entries := []string{shimDir, realDir}
	if inherited := os.Getenv("PATH"); inherited != "" {
		entries = append(entries, inherited)
	}
	path = strings.Join(entries, string(os.PathListSeparator))
	return shimPath, captureDir, path
}

func TestShimPassesArgvThroughUnchanged(t *testing.T) {
	shimPath, captureDir, path := shimEnv(t, "terraform", "#!/bin/sh\nprintf '%s\\n' \"$@\"\n")

	cmd := exec.Command(shimPath, "destroy", "-auto-approve", "--target=module.db")
	cmd.Env = append(os.Environ(), "PATH="+path, "DEPOSE_CAPTURE_DIR="+captureDir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run shim: %v", err)
	}

	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{"destroy", "-auto-approve", "--target=module.db"}
	if len(got) != len(want) {
		t.Fatalf("argv reaching the real binary = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestShimPropagatesExitCode(t *testing.T) {
	shimPath, captureDir, path := shimEnv(t, "kubectl", "#!/bin/sh\nexit 42\n")

	cmd := exec.Command(shimPath, "delete", "ns", "prod")
	cmd.Env = append(os.Environ(), "PATH="+path, "DEPOSE_CAPTURE_DIR="+captureDir)
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected a non-zero exit, got %v", err)
	}
	if code := exitErr.ExitCode(); code != 42 {
		t.Errorf("exit code = %d, want 42 (the real binary's code must survive)", code)
	}
}

func TestShimPropagatesSuccessExitCode(t *testing.T) {
	shimPath, captureDir, path := shimEnv(t, "aws", "#!/bin/sh\nexit 0\n")

	cmd := exec.Command(shimPath, "s3", "ls")
	cmd.Env = append(os.Environ(), "PATH="+path, "DEPOSE_CAPTURE_DIR="+captureDir)
	if err := cmd.Run(); err != nil {
		t.Errorf("expected exit 0, got %v", err)
	}
}

func TestShimForwardsStdin(t *testing.T) {
	shimPath, captureDir, path := shimEnv(t, "psql", "#!/bin/sh\ncat\n")

	cmd := exec.Command(shimPath, "-c", "SELECT 1")
	cmd.Env = append(os.Environ(), "PATH="+path, "DEPOSE_CAPTURE_DIR="+captureDir)
	cmd.Stdin = strings.NewReader("DROP TABLE users;\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run shim: %v", err)
	}

	if got := strings.TrimSpace(string(out)); got != "DROP TABLE users;" {
		t.Errorf("stdin reaching the real binary = %q, want %q", got, "DROP TABLE users;")
	}
}

func TestShimWritesCaptureRecordBeforeExec(t *testing.T) {
	shimPath, captureDir, path := shimEnv(t, "rm", "#!/bin/sh\nexit 0\n")

	cmd := exec.Command(shimPath, "-rf", "/data/training")
	cmd.Env = append(os.Environ(), "PATH="+path, "DEPOSE_CAPTURE_DIR="+captureDir)
	if err := cmd.Run(); err != nil {
		t.Fatalf("run shim: %v", err)
	}

	entries, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatalf("read capture dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("capture records written = %d, want 1", len(entries))
	}
	if !strings.HasSuffix(entries[0].Name(), ".json") {
		t.Errorf("capture record %q does not end in .json", entries[0].Name())
	}
}

func TestShimFailsClosedWhenRealBinaryMissing(t *testing.T) {
	shim := buildShim(t)
	shimDir := t.TempDir()
	captureDir := filepath.Join(t.TempDir(), "captures")

	shimPath := filepath.Join(shimDir, "terraform")
	if err := os.Symlink(shim, shimPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Only the shim dir on PATH, so there is no real terraform to reach.
	cmd := exec.Command(shimPath, "destroy")
	cmd.Env = append(os.Environ(), "PATH="+shimDir, "DEPOSE_CAPTURE_DIR="+captureDir)
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected a non-zero exit when the real binary is missing, got %v", err)
	}
	// 127 is the conventional "command not found" code.
	if code := exitErr.ExitCode(); code != 127 {
		t.Errorf("exit code = %d, want 127", code)
	}
}
