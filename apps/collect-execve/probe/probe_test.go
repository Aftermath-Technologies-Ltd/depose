package probe

import (
	"encoding/binary"
	"testing"
)

// The 32-byte record layout is the only contract between the assembled
// eBPF program and userspace. If one side changes, this is what catches
// it, because the kernel side cannot be exercised without CAP_BPF.

func sample(pid uint64, monoNs uint64, comm string) []byte {
	raw := make([]byte, eventSize)
	binary.LittleEndian.PutUint64(raw[0:8], pid)
	binary.LittleEndian.PutUint64(raw[8:16], monoNs)
	copy(raw[16:32], comm)
	return raw
}

func TestDecodeReadsPidMonotonicTimeAndComm(t *testing.T) {
	event, err := Decode(sample(4400, 123456789012345678, "terraform"))
	if err != nil {
		t.Fatal(err)
	}
	if event.PID != 4400 {
		t.Errorf("pid = %d, want 4400", event.PID)
	}
	if event.MonoNs != 123456789012345678 {
		t.Errorf("monoNs = %d", event.MonoNs)
	}
	if event.Comm != "terraform" {
		t.Errorf("comm = %q, want terraform", event.Comm)
	}
}

func TestDecodeStopsCommAtItsNulTerminator(t *testing.T) {
	raw := sample(1, 1, "bash")
	// Bytes past the terminator are whatever the kernel buffer held.
	copy(raw[16+5:32], "leftover")
	event, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.Comm != "bash" {
		t.Errorf("comm = %q, want bash", event.Comm)
	}
}

func TestDecodeKeepsAFullLengthCommWithNoTerminator(t *testing.T) {
	// TASK_COMM_LEN is 16 and the kernel does not terminate a name that
	// fills it, so the whole field is the name.
	full := "abcdefghijklmnop"
	event, err := Decode(sample(1, 1, full))
	if err != nil {
		t.Fatal(err)
	}
	if event.Comm != full {
		t.Errorf("comm = %q, want %q", event.Comm, full)
	}
}

func TestDecodeRejectsAShortRecord(t *testing.T) {
	if _, err := Decode(make([]byte, eventSize-1)); err == nil {
		t.Fatal("a short record must be an error, not a zero-valued exec")
	}
}
