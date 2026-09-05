// The execve record layout, shared by every platform.
//
// The bytes are written by the eBPF program on Linux and by nothing at
// all anywhere else, but the parser is pure and the layout is the only
// contract between the assembled program and userspace. Keeping it out
// of the build-tagged files means its tests run on every platform CI
// builds for, and means Event and ErrNotSupported are defined once
// rather than copied into two files that have to agree by hand.
package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNotSupported is returned when the platform has no eBPF at all.
var ErrNotSupported = errors.New("kernel execve capture needs Linux eBPF; on this platform DEPOSE captures through the agent hook only")

// eventSize is the fixed record the program writes: 8 bytes of pid, 8 of
// monotonic nanoseconds, 16 of comm.
const eventSize = 32

// commLen is TASK_COMM_LEN.
const commLen = 16

// Event is one exec as the kernel reported it.
type Event struct {
	PID    int
	MonoNs uint64
	Comm   string
}

// Decode parses one 32-byte ring buffer record.
//
// @param raw - The bytes the program wrote.
// @returns The decoded exec, or an error naming the size mismatch.
func Decode(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("execve ring buffer record is %d bytes, want %d", len(raw), eventSize)
	}
	comm := raw[16:32]
	if end := indexZero(comm); end >= 0 {
		comm = comm[:end]
	}
	return Event{
		PID:    int(binary.LittleEndian.Uint64(raw[0:8])),
		MonoNs: binary.LittleEndian.Uint64(raw[8:16]),
		Comm:   string(comm),
	}, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
