// Package procfs reads the parts of /proc the collector needs to turn a
// bare exec notification into a usable record: the argv, the working
// directory, and the chain of parents that says whether this process
// belongs to the agent at all.
//
// Every read races the process exiting. That is inherent to reading
// /proc after the fact and is why each accessor returns a zero value
// rather than an error when the entry is already gone: an exec that was
// witnessed but could not be characterized is still evidence, and
// pretending otherwise would drop it.
package procfs

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Reader reads process state from a procfs root. The root is a field so
// the tests can point it at a fixture tree instead of the live kernel.
type Reader struct {
	Root string
}

// New returns a reader over the real /proc.
func New() *Reader { return &Reader{Root: "/proc"} }

// MaxAncestryDepth caps the parent walk. A chain longer than this means
// a cycle in the data (which /proc should not produce, but a fixture or
// a pid reuse race can) and stopping is better than looping.
const MaxAncestryDepth = 32

// PPID returns a process's parent pid, or 0 when /proc/<pid>/stat is
// gone or unreadable.
//
// @param pid - The process to look up.
// @returns The parent pid, or 0.
func (r *Reader) PPID(pid int) int {
	data, err := os.ReadFile(filepath.Join(r.Root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	// Field 4 is ppid, but field 2 (comm) is parenthesized and may itself
	// contain spaces and parentheses, so the split starts after the last
	// ')' rather than at the second field.
	close := strings.LastIndexByte(string(data), ')')
	if close < 0 || close+2 >= len(data) {
		return 0
	}
	fields := strings.Fields(string(data[close+2:]))
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

// Ancestry walks parent pids from `pid` upwards, nearest first, stopping
// at pid 1, at a pid that no longer exists, or at MaxAncestryDepth.
//
// @param pid - The process to walk up from.
// @returns The parent chain, excluding `pid` itself.
func (r *Reader) Ancestry(pid int) []int {
	chain := make([]int, 0, 8)
	seen := map[int]bool{pid: true}
	current := pid
	for range MaxAncestryDepth {
		parent := r.PPID(current)
		if parent <= 0 || seen[parent] {
			break
		}
		chain = append(chain, parent)
		if parent == 1 {
			break
		}
		seen[parent] = true
		current = parent
	}
	return chain
}

// Argv returns the process's command line, or nil when it is gone.
//
// @param pid - The process to look up.
// @returns The argv, or nil.
func (r *Reader) Argv(pid int) []string {
	data, err := os.ReadFile(filepath.Join(r.Root, strconv.Itoa(pid), "cmdline"))
	if err != nil || len(data) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	argv := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			argv = append(argv, part)
		}
	}
	if len(argv) == 0 {
		return nil
	}
	return argv
}

// Exe returns the resolved executable path, or "" when it is gone.
//
// @param pid - The process to look up.
// @returns The absolute path, or "".
func (r *Reader) Exe(pid int) string {
	target, err := os.Readlink(filepath.Join(r.Root, strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return target
}

// Cwd returns the process's working directory, or "" when it is gone.
//
// @param pid - The process to look up.
// @returns The absolute path, or "".
func (r *Reader) Cwd(pid int) string {
	target, err := os.Readlink(filepath.Join(r.Root, strconv.Itoa(pid), "cwd"))
	if err != nil {
		return ""
	}
	return target
}

// Snapshot is everything the collector reads about one process.
type Snapshot struct {
	PPID     int
	Ancestry []int
	Argv     []string
	Exe      string
	Cwd      string
}

// Read takes one pass over a process. The ancestry walk starts at the
// parent, so the returned chain never contains `pid`.
//
// @param pid - The process that just exec'd.
// @returns What /proc still had for it.
func (r *Reader) Read(pid int) Snapshot {
	ancestry := r.Ancestry(pid)
	ppid := 0
	if len(ancestry) > 0 {
		ppid = ancestry[0]
	}
	return Snapshot{
		PPID:     ppid,
		Ancestry: ancestry,
		Argv:     r.Argv(pid),
		Exe:      r.Exe(pid),
		Cwd:      r.Cwd(pid),
	}
}
