//go:build linux

// Package probe attaches the execve tracepoint and streams what it sees.
//
// The eBPF program is assembled here in Go rather than compiled from C.
// That is a deliberate trade: no clang, no bpf2go, no generated object
// checked into the repository, and the whole program is visible in one
// screen of instructions that anyone auditing the capture path can read.
//
// The price is that the program has to stay small, so it does exactly
// three helper calls and writes a fixed 32-byte record:
//
//	u64 pid    from bpf_get_current_pid_tgid, upper half (the tgid)
//	u64 monoNs from bpf_ktime_get_ns
//	char comm[16] from bpf_get_current_comm
//
// It reads nothing out of the tracepoint context, which keeps it clear of
// the verifier's rules on context pointer arithmetic and means it does not
// depend on the tracepoint's field layout. Everything else about the
// process (argv, cwd, executable, ancestry) is read from /proc by the
// userspace half immediately afterwards; see package collector for what
// that costs and what it misses.
//
// Requires CAP_BPF and CAP_PERFMON (or root). Without them Open returns an
// error the caller records as a capture_failed rather than exiting hard.
package probe

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Probe is an attached tracepoint and its ring buffer.
type Probe struct {
	program *ebpf.Program
	events  *ebpf.Map
	link    link.Link
	reader  *ringbuf.Reader
}

// Open loads the program, attaches it to sched:sched_process_exec, and
// starts reading the ring buffer.
//
// @returns The running probe, or an error explaining what privilege or
// kernel feature is missing.
func Open() (*Probe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise the memlock limit: %w; run as root or grant CAP_BPF", err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "depose_execs",
		Type:       ebpf.RingBuf,
		MaxEntries: 1 << 20,
	})
	if err != nil {
		return nil, fmt.Errorf("create the execve ring buffer: %w; needs a kernel with BPF_MAP_TYPE_RINGBUF (5.8 or newer)", err)
	}

	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "depose_exec",
		Type:         ebpf.TracePoint,
		License:      "GPL",
		Instructions: instructions(events),
	})
	if err != nil {
		events.Close()
		return nil, fmt.Errorf("load the execve probe: %w; needs CAP_BPF (or root)", err)
	}

	attached, err := link.Tracepoint("sched", "sched_process_exec", program, nil)
	if err != nil {
		program.Close()
		events.Close()
		return nil, fmt.Errorf("attach to sched:sched_process_exec: %w; needs CAP_PERFMON (or root)", err)
	}

	reader, err := ringbuf.NewReader(events)
	if err != nil {
		attached.Close()
		program.Close()
		events.Close()
		return nil, fmt.Errorf("read the execve ring buffer: %w", err)
	}

	return &Probe{program: program, events: events, link: attached, reader: reader}, nil
}

// instructions assembles the probe.
//
// Registers: r6 holds the reserved record for the life of the program,
// which is why it is r6 and not a scratch register: r0 to r5 do not
// survive a helper call.
func instructions(events *ebpf.Map) asm.Instructions {
	dropped := "dropped"
	return asm.Instructions{
		// r0 = bpf_ringbuf_reserve(events, eventSize, 0)
		asm.LoadMapPtr(asm.R1, events.FD()),
		asm.Mov.Imm(asm.R2, eventSize),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		// A full ring buffer means the record is lost, not that the
		// program should fail: exit 0 and let the next exec through.
		asm.JEq.Imm(asm.R0, 0, dropped),
		asm.Mov.Reg(asm.R6, asm.R0),

		// record.pid = bpf_get_current_pid_tgid() >> 32
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.R6, 0, asm.R0, asm.DWord),

		// record.monoNs = bpf_ktime_get_ns()
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R6, 8, asm.R0, asm.DWord),

		// bpf_get_current_comm(&record.comm, commLen)
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Add.Imm(asm.R1, 16),
		asm.Mov.Imm(asm.R2, commLen),
		asm.FnGetCurrentComm.Call(),

		// bpf_ringbuf_submit(record, 0)
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol(dropped),
		asm.Return(),
	}
}

// Read blocks until the next exec arrives.
//
// @returns The exec, or an error. os.ErrClosed after Close.
func (p *Probe) Read() (Event, error) {
	sample, err := p.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return Event{}, os.ErrClosed
		}
		return Event{}, fmt.Errorf("read the execve ring buffer: %w", err)
	}
	return Decode(sample.RawSample)
}

// Close detaches the probe and releases the ring buffer.
func (p *Probe) Close() error {
	var first error
	for _, closer := range []func() error{p.reader.Close, p.link.Close, p.program.Close, p.events.Close} {
		if err := closer(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
