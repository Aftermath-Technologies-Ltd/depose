package procfs

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeProcess(t *testing.T, root string, pid, ppid int, comm string, argv []string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := strconv.Itoa(pid) + " (" + comm + ") S " + strconv.Itoa(ppid) + " 100 200"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	var cmdline []byte
	for _, arg := range argv {
		cmdline = append(cmdline, []byte(arg)...)
		cmdline = append(cmdline, 0)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), cmdline, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPPIDSurvivesACommWithSpacesAndParentheses(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, 42, 7, "gnome shell (wayland)", nil)
	r := &Reader{Root: root}

	if got := r.PPID(42); got != 7 {
		t.Errorf("ppid = %d, want 7; the comm field is parenthesized and may contain both", got)
	}
}

func TestPPIDIsZeroForAProcessThatIsGone(t *testing.T) {
	r := &Reader{Root: t.TempDir()}
	if got := r.PPID(42); got != 0 {
		t.Errorf("ppid = %d, want 0 for a process that has exited", got)
	}
}

func TestAncestryWalksToPidOne(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, 1, 0, "systemd", nil)
	writeProcess(t, root, 100, 1, "claude", nil)
	writeProcess(t, root, 200, 100, "bash", nil)
	writeProcess(t, root, 300, 200, "terraform", nil)
	r := &Reader{Root: root}

	got := r.Ancestry(300)
	want := []int{200, 100, 1}
	if len(got) != len(want) {
		t.Fatalf("ancestry = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ancestry = %v, want %v", got, want)
		}
	}
}

func TestAncestryStopsAtAMissingParent(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, 300, 200, "terraform", nil)
	r := &Reader{Root: root}

	got := r.Ancestry(300)
	if len(got) != 1 || got[0] != 200 {
		t.Errorf("ancestry = %v, want [200]; the walk stops where /proc stops", got)
	}
}

func TestAncestryDoesNotLoopOnACycle(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, 10, 20, "a", nil)
	writeProcess(t, root, 20, 10, "b", nil)
	r := &Reader{Root: root}

	got := r.Ancestry(10)
	if len(got) > MaxAncestryDepth {
		t.Fatalf("ancestry = %v, the walk did not terminate", got)
	}
	if len(got) != 1 || got[0] != 20 {
		t.Errorf("ancestry = %v, want [20]; a pid already seen ends the walk", got)
	}
}

func TestArgvSplitsOnNulAndDropsTheTrailingEmpty(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, 42, 1, "terraform", []string{"terraform", "destroy", "-auto-approve"})
	r := &Reader{Root: root}

	got := r.Argv(42)
	if len(got) != 3 || got[2] != "-auto-approve" {
		t.Errorf("argv = %v", got)
	}
}

func TestArgvIsNilForAKernelThreadOrAnExitedProcess(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, 42, 1, "kworker", nil)
	r := &Reader{Root: root}

	if got := r.Argv(42); got != nil {
		t.Errorf("argv = %v, want nil; an empty cmdline is not an empty command", got)
	}
	if got := r.Argv(999); got != nil {
		t.Errorf("argv = %v, want nil for a process that has exited", got)
	}
}

func TestReadReportsWhatSurvivedAndNothingMore(t *testing.T) {
	root := t.TempDir()
	writeProcess(t, root, 1, 0, "systemd", nil)
	writeProcess(t, root, 100, 1, "claude", nil)
	writeProcess(t, root, 200, 100, "terraform", []string{"terraform", "apply"})
	r := &Reader{Root: root}

	got := r.Read(200)
	if got.PPID != 100 {
		t.Errorf("ppid = %d, want 100", got.PPID)
	}
	if len(got.Argv) != 2 {
		t.Errorf("argv = %v", got.Argv)
	}
	// There is no exe or cwd symlink in the fixture, matching a process
	// whose /proc entry is partly gone.
	if got.Exe != "" || got.Cwd != "" {
		t.Errorf("exe = %q, cwd = %q, want both empty rather than invented", got.Exe, got.Cwd)
	}
}
