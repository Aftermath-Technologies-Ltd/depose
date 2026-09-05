// Package collector turns raw exec notifications into capture records.
//
// The kernel probe reports very little on purpose: a pid, a monotonic
// timestamp, and the 16-byte comm. Everything else is read from /proc
// immediately afterwards. That split keeps the eBPF program small enough
// to be obviously correct, and it means the collector's own logic is
// ordinary Go that can be tested without a kernel.
//
// The filter is the other half of the job. The capture store belongs to
// one session, so an exec is only recorded when the agent's pid is in
// its ancestry. Children of children count: an agent that spawns a shell
// that spawns terraform is exactly the case the hook misses.
package collector

import (
	"fmt"
	"time"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/procfs"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/record"
)

// Exec is what the kernel probe reports.
type Exec struct {
	PID    int
	MonoNs uint64
	Comm   string
}

// Options configure one collector run.
type Options struct {
	// AgentPID roots the process tree that is in scope. An exec is only
	// recorded when this pid is among its ancestors.
	AgentPID int
	// SessionID is stamped on every record so the normalizer can scope
	// the store to one session.
	SessionID string
	// CaptureDir is the DEPOSE capture store.
	CaptureDir string
}

// Collector holds the pieces one run needs, with the I/O injected so the
// pipeline can be driven end to end in a test.
type Collector struct {
	Options Options
	Proc    *procfs.Reader
	// Now supplies the wall-clock time stamped on a record.
	Now func() time.Time
	// Write stores a record and returns its path. Defaults to record.Write.
	Write func(dir string, r record.Execve) (string, error)
}

// New builds a collector over the live /proc and the real capture store.
//
// @param options - Agent pid, session id, and capture directory.
// @returns A ready collector.
func New(options Options) *Collector {
	return &Collector{
		Options: options,
		Proc:    procfs.New(),
		Now:     time.Now,
		Write:   record.Write,
	}
}

// Result reports what one run did, for the CLI to print and for the
// overhead measurement to divide by.
type Result struct {
	// Seen is every exec the probe reported.
	Seen int
	// Recorded is the subset inside the agent's process tree.
	Recorded int
	// Uncharacterized counts recorded execs whose process had already
	// exited before /proc could be read, so argv is empty.
	Uncharacterized int
}

// Handle processes one exec notification.
//
// Returns false when the exec was outside the agent's process tree and
// nothing was written, which is the common case on a busy machine.
//
// @param e - The exec the probe reported.
// @param result - Counters updated in place.
// @returns An error only when a record was in scope and could not be written.
func (c *Collector) Handle(e Exec, result *Result) error {
	result.Seen++
	if e.PID == c.Options.AgentPID {
		return nil
	}
	snapshot := c.Proc.Read(e.PID)
	if !inTree(snapshot.Ancestry, c.Options.AgentPID) {
		return nil
	}
	if len(snapshot.Argv) == 0 {
		result.Uncharacterized++
	}
	exe := snapshot.Exe
	if exe == "" && len(snapshot.Argv) > 0 {
		exe = snapshot.Argv[0]
	}
	r := record.New(
		e.PID, snapshot.PPID, snapshot.Ancestry, e.Comm, exe,
		snapshot.Argv, snapshot.Cwd, e.MonoNs, c.Now(), c.Options.SessionID,
	)
	if _, err := c.Write(c.Options.CaptureDir, r); err != nil {
		return fmt.Errorf("record execve of pid %d: %w", e.PID, err)
	}
	result.Recorded++
	return nil
}

func inTree(ancestry []int, agentPID int) bool {
	for _, pid := range ancestry {
		if pid == agentPID {
			return true
		}
	}
	return false
}
