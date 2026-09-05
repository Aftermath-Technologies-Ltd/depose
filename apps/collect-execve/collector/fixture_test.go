package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/collect-execve/record"
)

// The capture store is the boundary between this collector and the
// TypeScript normalizer, and neither side can call the other. This test
// writes the fixture store that packages/core/test/normalize.kernel.test.ts
// reads back, so a change to the record shape on either side breaks a
// test rather than silently dropping kernel evidence. Regenerate with:
//
//	DEPOSE_WRITE_GOLDEN=1 go test ./collector/ -run Fixture
func TestFixtureStoreMatchesWhatIsCheckedIn(t *testing.T) {
	fixtures := map[string]record.Execve{
		// A witnessed exec inside the agent's tree.
		"01JKRNV0000000000000000001": record.New(
			5100, 4300, []int{4300, 4200, 1}, "terraform", "/usr/bin/terraform",
			[]string{"terraform", "destroy", "-auto-approve"}, "/srv/pocketos",
			1747583400000000000, time.Date(2025, 5, 18, 15, 30, 10, 0, time.UTC), "sess-kernel"),
		// An exec the collector saw and could not characterize.
		"01JKRNV0000000000000000002": record.New(
			5200, 4300, []int{4300, 4200, 1}, "curl", "",
			nil, "", 1747583401000000000, time.Date(2025, 5, 18, 15, 30, 11, 0, time.UTC), "sess-kernel"),
	}

	dir := filepath.Join("..", "testdata", "store")
	if os.Getenv("DEPOSE_WRITE_GOLDEN") == "1" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for id, r := range fixtures {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, id+".json")
		if os.Getenv("DEPOSE_WRITE_GOLDEN") == "1" {
			if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		onDisk, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture %s: %v; regenerate with DEPOSE_WRITE_GOLDEN=1", path, err)
		}
		if string(onDisk) != string(data)+"\n" {
			t.Errorf("fixture %s is stale; regenerate with DEPOSE_WRITE_GOLDEN=1", path)
		}
	}
}
