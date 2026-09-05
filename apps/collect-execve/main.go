// Command depose-collect-execve records the execve calls the kernel sees
// inside an agent's process tree, so the commands the agent hook cannot
// see (an absolute path that bypasses the shim, a subprocess.run with
// shell=False, a static binary that execs a child of its own) end up in
// the bundle as their own events instead of being silently absent.
//
// It is optional. Without CAP_BPF the collector writes a capture_failed
// record into the capture store and exits 0: the bundle then discloses
// that kernel witnessing was requested and unavailable, which is the
// honest outcome, rather than looking like a session where nothing ran
// outside the hook.
//
//	depose-collect-execve --session <id> --pid <agent pid> [--capture-dir <dir>] [--duration 30m]
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/collector"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/failure"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/probe"
)

func main() {
	session := flag.String("session", "", "agent session id to stamp on every record (required)")
	agentPID := flag.Int("pid", 0, "pid of the agent whose process tree is in scope (default: the parent of this process)")
	captureDir := flag.String("capture-dir", "", "capture store; defaults to $DEPOSE_CAPTURE_DIR then ~/.depose/captures")
	duration := flag.Duration("duration", 0, "stop after this long; 0 runs until interrupted")
	flag.Parse()

	dir := resolveCaptureDir(*captureDir)
	pid := *agentPID
	if pid == 0 {
		pid = os.Getppid()
	}

	if err := run(collector.Options{AgentPID: pid, SessionID: *session, CaptureDir: dir}, *duration); err != nil {
		// The collector never fails the session it is observing. It
		// records why it could not witness anything and exits 0.
		phase := "ebpf-attach"
		if errors.Is(err, probe.ErrNotSupported) {
			phase = "ebpf-unsupported"
		}
		path, writeErr := failure.Write(dir, phase, err, *session)
		if writeErr != nil {
			fmt.Fprintf(os.Stderr, "depose-collect-execve: %v (and the failure could not be recorded: %v)\n", err, writeErr)
			return
		}
		fmt.Fprintf(os.Stderr, "depose-collect-execve: %v (recorded as %s)\n", err, filepath.Base(path))
		return
	}
}

func run(options collector.Options, duration time.Duration) error {
	p, err := probe.Open()
	if err != nil {
		return err
	}
	defer p.Close()

	c := collector.New(options)
	var result collector.Result
	started := time.Now()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		if duration > 0 {
			select {
			case <-stop:
			case <-time.After(duration):
			}
		} else {
			<-stop
		}
		p.Close()
	}()

	fmt.Fprintf(os.Stderr, "depose-collect-execve: watching the process tree under pid %d\n", options.AgentPID)
	for {
		event, err := p.Read()
		if errors.Is(err, os.ErrClosed) {
			break
		}
		if err != nil {
			return err
		}
		if err := c.Handle(collector.Exec{PID: event.PID, MonoNs: event.MonoNs, Comm: event.Comm}, &result); err != nil {
			return err
		}
	}

	elapsed := time.Since(started)
	fmt.Fprintf(os.Stderr,
		"depose-collect-execve: %d exec(s) seen, %d in the agent's tree, %d uncharacterized, over %s\n",
		result.Seen, result.Recorded, result.Uncharacterized, elapsed.Round(time.Millisecond))
	return nil
}

func resolveCaptureDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if fromEnv := os.Getenv("DEPOSE_CAPTURE_DIR"); fromEnv != "" {
		return fromEnv
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".depose-captures"
	}
	return filepath.Join(home, ".depose", "captures")
}
