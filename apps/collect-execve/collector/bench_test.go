package collector

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/procfs"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/record"
)

// BenchmarkHandle measures the userspace half of the collector: the
// /proc reads, the ancestry walk, and the record write. The kernel half
// (the tracepoint and the ring buffer) cannot be benchmarked without
// CAP_BPF; see docs/capture-coverage.md for what is and is not measured.
func BenchmarkHandle(b *testing.B) {
	root := b.TempDir()
	for pid, ppid := range map[int]int{4200: 1, 4300: 4200, 4400: 4300} {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		stat := strconv.Itoa(pid) + " (proc) S " + strconv.Itoa(ppid) + " 0 0 0"
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			b.Fatal(err)
		}
		cmdline := []byte("terraform\x00destroy\x00-auto-approve\x00")
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), cmdline, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	c := &Collector{
		Options: Options{AgentPID: 4200, SessionID: "sess", CaptureDir: b.TempDir()},
		Proc:    &procfs.Reader{Root: root},
		Now:     time.Now,
		Write:   record.Write,
	}
	var result Result
	b.ResetTimer()
	for b.Loop() {
		if err := c.Handle(Exec{PID: 4400, MonoNs: 1, Comm: "terraform"}, &result); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFilter measures the common case on a busy machine: an exec
// outside the agent's process tree, which costs one ancestry walk and
// no write.
func BenchmarkFilter(b *testing.B) {
	root := b.TempDir()
	for pid, ppid := range map[int]int{9000: 1, 9002: 9000} {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		stat := strconv.Itoa(pid) + " (proc) S " + strconv.Itoa(ppid) + " 0 0 0"
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	c := &Collector{
		Options: Options{AgentPID: 4200, CaptureDir: b.TempDir()},
		Proc:    &procfs.Reader{Root: root},
		Now:     time.Now,
		Write:   record.Write,
	}
	var result Result
	b.ResetTimer()
	for b.Loop() {
		if err := c.Handle(Exec{PID: 9002, MonoNs: 1, Comm: "aws"}, &result); err != nil {
			b.Fatal(err)
		}
	}
}
