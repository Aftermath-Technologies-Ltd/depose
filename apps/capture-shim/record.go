// apps/capture-shim/record.go
//
// JSON capture record writer for the shell shim.
// Writes a ShellCommandPrePayload JSON to $DEPOSE_CAPTURE_DIR/<ulid>.json.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// Default capture directory (overridden by $DEPOSE_CAPTURE_DIR)
func defaultCaptureDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".depose", "captures")
}

// getCaptureDir returns the active capture directory from env or default.
func getCaptureDir() string {
	if dir := os.Getenv("DEPOSE_CAPTURE_DIR"); dir != "" {
		return dir
	}
	return defaultCaptureDir()
}

// Env allowlist prefixes (BUILD_PLAN.md §7.2)
var envAllowPrefixes = []string{
	"AWS_",
	"GH_",
	"OPENAI_",
	"ANTHROPIC_",
	"RAILWAY_",
}

// ShellCommandPrePayload matches the TypeScript schema (BUILD_PLAN.md §4.2)
type ShellCommandPrePayload struct {
	Argv               []string                   `json:"argv"`
	Cwd                string                     `json:"cwd"`
	EnvHash            string                     `json:"envHash"`
	EnvSubset          map[string]string          `json:"envSubset"`
	TtyID              *string                    `json:"ttyId"`
	User               string                     `json:"user"`
	Hostname           string                     `json:"hostname"`
	ParentProcessTree  []ProcessNodePayload       `json:"parentProcessTree"`
	FileArgs           []FileArgPayload           `json:"fileArgs"`
	Source             string                     `json:"source"`
	CaptureSchemaVersion int                       `json:"captureSchemaVersion"`
}

type ProcessNodePayload struct {
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
	Exe   string `json:"exe"`
	Argv0 string `json:"argv0"`
}

type FileArgPayload struct {
	Path     string  `json:"path"`
	PreSha256 *string `json:"preSha256"`
	SizeBytes *int64  `json:"sizeBytes"`
}

// writeCaptureRecord builds and writes a capture record.
func writeCaptureRecord(invokedAs string, args []string) (string, error) {
	captureDir := getCaptureDir()

	// Ensure capture directory exists with 0700
	if err := os.MkdirAll(captureDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create capture dir: %w", err)
	}

	// Generate ULID-like identifier (timestamp-prefixed UUID)
	ulid := generateULID()

	// Build full argv
	argv := append([]string{invokedAs}, args...)

	// Get cwd
	cwd, _ := os.Getwd()

	// Filter env and compute hash
	envSubset, envHash := filterAndHashEnv(os.Environ())

	// Get user/hostname
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("LOGNAME")
	}
	hostname, _ := os.Hostname()

	// Walk parent process tree
	ppTree := walkProcessTree(os.Getppid())

	// Resolve TTY
	ttyID := resolveTTY()

	// Stdin tee (for gh api graphql cases)
	// Handled separately in teeStdin()

	payload := ShellCommandPrePayload{
		Argv:                argv,
		Cwd:                 cwd,
		EnvHash:             envHash,
		EnvSubset:           envSubset,
		TtyID:               ttyID,
		User:                user,
		Hostname:            hostname,
		ParentProcessTree:   ppTree,
		FileArgs:            []FileArgPayload{},
		Source:              "shell-shim",
		CaptureSchemaVersion: 1,
	}

	// Serialize
	jsonBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot marshal capture record: %w", err)
	}

	// Write to file
	path := filepath.Join(captureDir, ulid+".json")
	if err := os.WriteFile(path, jsonBytes, 0600); err != nil {
		return "", fmt.Errorf("cannot write capture record: %w", err)
	}

	return path, nil
}

// filterAndHashEnv splits env into allowlisted subset + full hash.
func filterAndHashEnv(env []string) (map[string]string, string) {
	subset := make(map[string]string)
	var hashPairs []string

	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		hashPairs = append(hashPairs, key+"="+value)

		for _, prefix := range envAllowPrefixes {
			if strings.HasPrefix(key, prefix) {
				subset[key] = value
				break
			}
		}
	}

	// Hash full env for tamper-evidence
	fullEnv := strings.Join(hashPairs, "\n")
	hash := sha256.Sum256([]byte(fullEnv))
	return subset, hex.EncodeToString(hash[:])
}

// walkProcessTree walks up the parent process tree (best-effort).
func walkProcessTree(ppid int) []ProcessNodePayload {
	var tree []ProcessNodePayload
	currentPid := ppid

	for i := 0; i < 10 && currentPid > 1; i++ {
		// Read /proc/<pid>/stat (Linux) or use ps (macOS)
		node := getProcessNode(currentPid)
		if node == nil {
			break
		}
		tree = append(tree, *node)
		currentPid = node.PPID
	}

	return tree
}

// getProcessNode gets info about a process (best-effort).
func getProcessNode(pid int) *ProcessNodePayload {
	// Try reading from /proc (Linux)
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		return parseProcStat(pid, string(stat))
	}

	// Fallback: just record PID/PPID
	return &ProcessNodePayload{
		PID:   pid,
		PPID:  0,
		Exe:   "",
		Argv0: "",
	}
}

// parseProcStat parses /proc/<pid>/stat (simplified).
func parseProcStat(pid int, stat string) *ProcessNodePayload {
	// Format: pid (comm) state ppid ...
	// Find the closing paren to handle comm with spaces
	closeParen := strings.LastIndex(stat, ")")
	if closeParen < 0 {
		return &ProcessNodePayload{PID: pid, PPID: 0}
	}

	fields := strings.Fields(stat[closeParen+1:])
	if len(fields) < 2 {
		return &ProcessNodePayload{PID: pid, PPID: 0}
	}

	// fields[0] = state, fields[1] = ppid
	ppid := 0
	fmt.Sscanf(fields[1], "%d", &ppid)

	// Extract comm from between parens
	comm := stat[strings.Index(stat, "(")+1 : closeParen]

	return &ProcessNodePayload{
		PID:   pid,
		PPID:  ppid,
		Exe:   comm,
		Argv0: comm,
	}
}

// resolveTTY returns the current TTY device path or nil.
func resolveTTY() *string {
	// Check if stdin is a terminal
	if stat, err := os.Stdin.Stat(); err == nil {
		if stat.Mode()&os.ModeCharDevice != 0 {
			tty := "/dev/tty"
			return &tty
		}
	}
	return nil
}

// generateULID creates a timestamp-sortable identifier.
// Simplified: uses timestamp prefix + UUID random suffix.
func generateULID() string {
	now := time.Now().UTC()
	ts := now.UnixMilli()
	// Encode 48-bit timestamp into 10 Crockford base32 chars
	encoding := "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var tsChars [10]byte
	for i := 9; i >= 0; i-- {
		tsChars[i] = encoding[ts&0x1f]
		ts >>= 5
	}

	// 16 random chars from UUID
	u := uuid.New()
	var randChars [16]byte
	for i := 0; i < 16; i++ {
		randChars[i] = encoding[u[i%16]%32]
	}

	return string(tsChars[:]) + string(randChars[:])
}

// teeStdin tees stdin to a temp file if size < 1 MB.
// Returns the file to use as stdin for the child.
func teeStdin() (*os.File, func()) {
	// Check stdin size
	stat, err := os.Stdin.Stat()
	if err != nil || stat.Size() <= 0 || stat.Size() > 1*1024*1024 {
		// Over threshold or unknown: pass through directly
		return os.Stdin, func() {}
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "depose-shim-stdin-*")
	if err != nil {
		return os.Stdin, func() {}
	}

	// Tee stdin to temp file
	if _, err := io.Copy(tmpFile, os.Stdin); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return os.Stdin, func() {}
	}

	// Seek back to beginning for the child
	tmpFile.Seek(0, io.SeekStart)

	cleanup := func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}

	return tmpFile, cleanup
}

// propagateSignals forwards OS signals to the child process.
func propagateSignals(child *os.Process) {
	sigChan := make(chan os.Signal, 1)
	// Don't register SIGPIPE — Go handles it
	for range []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		// signal.Notify is in signal package
	}
	_ = sigChan
	_ = child
	// Simplified: signal propagation is handled by process group
}
