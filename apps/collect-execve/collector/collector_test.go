package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/procfs"
	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/record"
)

// fakeProc builds a procfs tree so the filter and the enrichment can be
// driven without spawning processes. Each entry is pid -> (ppid, argv).
func fakeProc(t *testing.T, entries map[int]struct {
	ppid int
	argv []string
}) *procfs.Reader {
	t.Helper()
	root := t.TempDir()
	for pid, entry := range entries {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// The comm field is parenthesized and may contain spaces and
		// parentheses of its own, which is what makes stat parsing
		// interesting; the fixture uses a name that exercises that.
		stat := strconv.Itoa(pid) + " (weird (name) ) S " + strconv.Itoa(entry.ppid) + " 0 0 0"
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
		var cmdline []byte
		for _, arg := range entry.argv {
			cmdline = append(cmdline, []byte(arg)...)
			cmdline = append(cmdline, 0)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), cmdline, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &procfs.Reader{Root: root}
}

func newCollector(t *testing.T, proc *procfs.Reader, agentPID int) (*Collector, *[]record.Execve) {
	t.Helper()
	var written []record.Execve
	c := &Collector{
		Options: Options{AgentPID: agentPID, SessionID: "sess-kernel", CaptureDir: t.TempDir()},
		Proc:    proc,
		Now:     func() time.Time { return time.Date(2025, 5, 18, 15, 30, 0, 0, time.UTC) },
		Write: func(_ string, r record.Execve) (string, error) {
			written = append(written, r)
			return "record.json", nil
		},
	}
	return c, &written
}

func TestRecordsAnExecInsideTheAgentTree(t *testing.T) {
	proc := fakeProc(t, map[int]struct {
		ppid int
		argv []string
	}{
		4200: {ppid: 1, argv: []string{"/usr/bin/claude"}},
		4300: {ppid: 4200, argv: []string{"/bin/bash", "-c", "terraform destroy"}},
		4400: {ppid: 4300, argv: []string{"/usr/bin/terraform", "destroy", "-auto-approve"}},
	})
	c, written := newCollector(t, proc, 4200)

	var result Result
	if err := c.Handle(Exec{PID: 4400, MonoNs: 99, Comm: "terraform"}, &result); err != nil {
		t.Fatal(err)
	}

	if result.Recorded != 1 || result.Seen != 1 || result.Uncharacterized != 0 {
		t.Fatalf("result = %+v, want 1 seen, 1 recorded, 0 uncharacterized", result)
	}
	got := (*written)[0]
	if got.PPID != 4300 {
		t.Errorf("ppid = %d, want 4300", got.PPID)
	}
	if len(got.Ancestry) != 3 || got.Ancestry[0] != 4300 || got.Ancestry[1] != 4200 || got.Ancestry[2] != 1 {
		t.Errorf("ancestry = %v, want [4300 4200 1]", got.Ancestry)
	}
	if len(got.Argv) != 3 || got.Argv[0] != "/usr/bin/terraform" {
		t.Errorf("argv = %v", got.Argv)
	}
	if got.MonoNs != "99" || got.Source != "kernel" || got.Kind != "execve" {
		t.Errorf("record = %+v", got)
	}
	if got.SessionID == nil || *got.SessionID != "sess-kernel" {
		t.Errorf("sessionId = %v, want sess-kernel", got.SessionID)
	}
}

func TestIgnoresAnExecOutsideTheAgentTree(t *testing.T) {
	proc := fakeProc(t, map[int]struct {
		ppid int
		argv []string
	}{
		4200: {ppid: 1, argv: []string{"/usr/bin/claude"}},
		9000: {ppid: 1, argv: []string{"/usr/bin/firefox"}},
		9002: {ppid: 9000, argv: []string{"/usr/local/bin/aws", "s3", "rb", "s3://prod"}},
	})
	c, written := newCollector(t, proc, 4200)

	var result Result
	if err := c.Handle(Exec{PID: 9002, MonoNs: 1, Comm: "aws"}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Recorded != 0 || len(*written) != 0 {
		t.Fatalf("an exec outside the agent's tree must not enter the session's capture store: %+v", result)
	}
	if result.Seen != 1 {
		t.Errorf("seen = %d, want 1; the collector still counts what it filtered out", result.Seen)
	}
}

func TestDoesNotRecordTheAgentsOwnExec(t *testing.T) {
	proc := fakeProc(t, map[int]struct {
		ppid int
		argv []string
	}{4200: {ppid: 1, argv: []string{"/usr/bin/claude"}}})
	c, written := newCollector(t, proc, 4200)

	var result Result
	if err := c.Handle(Exec{PID: 4200, MonoNs: 1, Comm: "claude"}, &result); err != nil {
		t.Fatal(err)
	}
	if len(*written) != 0 {
		t.Fatal("the agent's own exec is not a command the agent ran")
	}
}

func TestRecordsAnExecItCouldNotCharacterize(t *testing.T) {
	// The process exited before /proc could be read: only the pid, the
	// comm, and the timestamp survive. The record is still written,
	// because "something ran here and we lost the detail" is the finding.
	proc := fakeProc(t, map[int]struct {
		ppid int
		argv []string
	}{
		4200: {ppid: 1, argv: []string{"/usr/bin/claude"}},
		4400: {ppid: 4200, argv: nil},
	})
	c, written := newCollector(t, proc, 4200)

	var result Result
	if err := c.Handle(Exec{PID: 4400, MonoNs: 7, Comm: "curl"}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Recorded != 1 || result.Uncharacterized != 1 {
		t.Fatalf("result = %+v, want it recorded and counted as uncharacterized", result)
	}
	got := (*written)[0]
	if len(got.Argv) != 0 || got.Exe != "" {
		t.Errorf("argv and exe must stay empty rather than be guessed: %+v", got)
	}
	if got.Comm != "curl" {
		t.Errorf("comm = %q, want curl; it is all the kernel gave us", got.Comm)
	}
}

func TestWrittenRecordMatchesTheReaderShape(t *testing.T) {
	// The TypeScript reader dispatches on `kind` and requires pid, argv,
	// and a parseable capturedAt. Anything else it fills with defaults,
	// so those four are the contract.
	dir := t.TempDir()
	r := record.New(4400, 4300, []int{4300, 4200}, "terraform", "/usr/bin/terraform",
		[]string{"terraform", "destroy"}, "/srv", 12345, time.Date(2025, 5, 18, 15, 30, 0, 0, time.UTC), "sess")
	path, err := record.Write(dir, r)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %v, want 0600; the store holds command lines", info.Mode().Perm())
	}
	base := filepath.Base(path)
	if len(base) != len("01ARZ3NDEKTSV4RRFFQ69G5FAV.json") {
		t.Errorf("record filename %q is not a 26-character ULID plus .json", base)
	}

	var parsed map[string]interface{}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["kind"] != "execve" || parsed["source"] != "kernel" {
		t.Errorf("record = %v", parsed)
	}
	if parsed["monoNs"] != "12345" {
		t.Errorf("monoNs = %v, want the string \"12345\"; a number loses precision past 2^53", parsed["monoNs"])
	}
	if parsed["capturedAt"] != "2025-05-18T15:30:00.000Z" {
		t.Errorf("capturedAt = %v", parsed["capturedAt"])
	}
	if _, err := time.Parse(time.RFC3339, parsed["capturedAt"].(string)); err != nil {
		t.Errorf("capturedAt does not parse as RFC 3339: %v", err)
	}
}

func TestEmptyListsSerializeAsArraysNotNull(t *testing.T) {
	// A null argv would fail the reader's Array.isArray check and the
	// record would be dropped as malformed.
	r := record.New(1, 0, nil, "x", "", nil, "", 0, time.Now(), "")
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["argv"].([]interface{}); !ok {
		t.Errorf("argv = %v, want []", parsed["argv"])
	}
	if _, ok := parsed["ancestry"].([]interface{}); !ok {
		t.Errorf("ancestry = %v, want []", parsed["ancestry"])
	}
	if parsed["sessionId"] != nil {
		t.Errorf("sessionId = %v, want null when the collector was given no session", parsed["sessionId"])
	}
}
