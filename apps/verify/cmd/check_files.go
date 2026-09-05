// Package cmd, files-map and attestation-file checks.
//
// The files map (manifest.files) pins every file in the bundle tree except
// manifest.json, attestations/signatures.json, and the .tsr files, which
// are bound to the manifest another way: signatures.json must carry the
// same blocks as manifest.signatures, and each .tsr must be the byte
// decoding of the corresponding manifest.timestamps[i].tokenBase64, which
// timestamp-verify has already tied to the manifest hash.
package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Aftermath-Technologies-Ltd/depose/apps/verify/manifest"
)

// filesMapExcluded reports whether a relative path is deliberately
// absent from the files map. Mirrors FILES_MAP_EXCLUDED in
// packages/bundle/src/files-map.ts.
func filesMapExcluded(rel string) bool {
	switch rel {
	case "manifest.json", "attestations/signatures.json", anchorPath:
		return true
	}
	return strings.HasPrefix(rel, "attestations/rfc3161-timestamps/")
}

// safeRelativePath rejects map keys that could escape the bundle root.
func safeRelativePath(rel string) error {
	if rel == "" {
		return fmt.Errorf("empty key")
	}
	if strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return fmt.Errorf("key %q is absolute or uses backslashes", rel)
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("key %q contains a %q segment", rel, seg)
		}
	}
	return nil
}

// walkBundleFiles lists every regular file under bundlePath as a
// forward-slash relative path, in lexicographic order. Symlinks and
// non-regular files are returned as errors rather than skipped.
func walkBundleFiles(bundlePath string) ([]string, []string, error) {
	var files, symlinks []string
	err := filepath.WalkDir(bundlePath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == bundlePath {
			return nil
		}
		rel, err := filepath.Rel(bundlePath, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			symlinks = append(symlinks, rel)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		files = append(files, rel)
		return nil
	})
	sort.Strings(files)
	return files, symlinks, err
}

// checkFilesMap walks the tree and compares it against manifest.files.
// A v2 bundle predates the map: that is reported as a downgrade, not a
// failure, because the schema never promised it. A v3 bundle without a
// map, or with any discrepancy, fails.
func checkFilesMap(bundlePath string, m *manifest.Manifest) CheckResult {
	if m.Files == nil {
		if m.SchemaVersion < 3 {
			return CheckResult{
				Name:   "files-map",
				Status: StatusWarn,
				Detail: fmt.Sprintf("schemaVersion %d predates the signed files map: raw/, narrative, and verify.txt are NOT integrity-covered in this bundle", m.SchemaVersion),
			}
		}
		return CheckResult{Name: "files-map", Status: StatusFail, Detail: "manifest.files is missing; a schemaVersion 3 bundle must pin every file in its tree"}
	}

	onDisk, symlinks, err := walkBundleFiles(bundlePath)
	if err != nil {
		return CheckResult{Name: "files-map", Status: StatusFail, Detail: fmt.Sprintf("cannot walk bundle tree: %v", err)}
	}
	if len(symlinks) > 0 {
		return CheckResult{Name: "files-map", Status: StatusFail, Detail: fmt.Sprintf("bundle contains symlink(s), which are forbidden: %s", strings.Join(symlinks, ", "))}
	}

	var problems []string
	for key := range m.Files {
		if err := safeRelativePath(key); err != nil {
			problems = append(problems, fmt.Sprintf("unsafe key: %v", err))
		}
		if filesMapExcluded(key) {
			problems = append(problems, fmt.Sprintf("%s must not appear in the files map", key))
		}
	}
	seen := make(map[string]bool, len(onDisk))
	checked := 0
	for _, rel := range onDisk {
		if filesMapExcluded(rel) {
			continue
		}
		seen[rel] = true
		entry, ok := m.Files[rel]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s is on disk but not in the files map (added after sealing)", rel))
			continue
		}
		data, err := os.ReadFile(filepath.Join(bundlePath, filepath.FromSlash(rel)))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: cannot read: %v", rel, err))
			continue
		}
		if int64(len(data)) != entry.Bytes {
			problems = append(problems, fmt.Sprintf("%s: length mismatch (map=%d bytes, disk=%d bytes)", rel, entry.Bytes, len(data)))
			continue
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), entry.Sha256) {
			problems = append(problems, fmt.Sprintf("%s: sha256 mismatch (map=%s..., disk=%s...)", rel, truncHex(entry.Sha256, 16), truncHex(hex.EncodeToString(sum[:]), 16)))
			continue
		}
		checked++
	}
	missing := make([]string, 0)
	for key := range m.Files {
		if !seen[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		problems = append(problems, fmt.Sprintf("%s is in the files map but not on disk (deleted after sealing)", key))
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return CheckResult{Name: "files-map", Status: StatusFail, Detail: fmt.Sprintf("%d problem(s): %s", len(problems), strings.Join(problems, "; "))}
	}
	return CheckResult{Name: "files-map", Status: StatusPass, Detail: fmt.Sprintf("all %d file(s) in the tree match the signed files map", checked)}
}

// checkAttestationFiles binds the on-disk attestation artifacts to the
// manifest: signatures.json must carry the manifest's signature blocks,
// and every .tsr must be the decoded manifest token, no more, no fewer.
func checkAttestationFiles(bundlePath string, m *manifest.Manifest) CheckResult {
	var problems []string

	sigPath := filepath.Join(bundlePath, "attestations", "signatures.json")
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		problems = append(problems, fmt.Sprintf("attestations/signatures.json: %v", err))
	} else {
		var onDisk struct {
			Blocks []manifest.SignatureBlock `json:"blocks"`
		}
		if err := json.Unmarshal(raw, &onDisk); err != nil {
			problems = append(problems, fmt.Sprintf("attestations/signatures.json: malformed: %v", err))
		} else if len(onDisk.Blocks) != len(m.Signatures) {
			problems = append(problems, fmt.Sprintf("attestations/signatures.json has %d block(s), manifest has %d", len(onDisk.Blocks), len(m.Signatures)))
		} else {
			for i := range onDisk.Blocks {
				if onDisk.Blocks[i] != m.Signatures[i] {
					problems = append(problems, fmt.Sprintf("attestations/signatures.json block[%d] differs from manifest.signatures[%d]", i, i))
				}
			}
		}
	}

	tsrDir := filepath.Join(bundlePath, "attestations", "rfc3161-timestamps")
	entries, _ := os.ReadDir(tsrDir)
	onDiskTsr := make(map[string]bool)
	for _, e := range entries {
		if !e.IsDir() {
			onDiskTsr[e.Name()] = true
		}
	}
	if doc, _, err := loadAnchor(bundlePath); err == nil && doc != nil {
		for i, tok := range doc.Timestamps {
			name := filepath.Base(tok.File)
			want, err := base64.StdEncoding.DecodeString(tok.TokenBase64)
			if err != nil {
				problems = append(problems, fmt.Sprintf("anchor.timestamps[%d].tokenBase64 is not base64", i))
				continue
			}
			got, err := os.ReadFile(filepath.Join(tsrDir, name))
			if err != nil {
				problems = append(problems, fmt.Sprintf("attestations/rfc3161-timestamps/%s is missing (named by the anchor)", name))
				continue
			}
			delete(onDiskTsr, name)
			if !bytes.Equal(got, want) {
				problems = append(problems, fmt.Sprintf("attestations/rfc3161-timestamps/%s does not match anchor.timestamps[%d]", name, i))
			}
		}
	}

	for i, tok := range m.Timestamps {
		name := fmt.Sprintf("%d.tsr", i)
		want, err := base64.StdEncoding.DecodeString(tok.TokenBase64)
		if err != nil {
			problems = append(problems, fmt.Sprintf("manifest.timestamps[%d].tokenBase64 is not base64", i))
			continue
		}
		got, err := os.ReadFile(filepath.Join(tsrDir, name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("attestations/rfc3161-timestamps/%s is missing (deleted after sealing)", name))
			continue
		}
		delete(onDiskTsr, name)
		if !bytes.Equal(got, want) {
			problems = append(problems, fmt.Sprintf("attestations/rfc3161-timestamps/%s does not match manifest.timestamps[%d]", name, i))
		}
	}
	extra := make([]string, 0, len(onDiskTsr))
	for name := range onDiskTsr {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	for _, name := range extra {
		problems = append(problems, fmt.Sprintf("attestations/rfc3161-timestamps/%s is named by neither the manifest nor the anchor (added after sealing)", name))
	}

	if len(problems) > 0 {
		return CheckResult{Name: "attestation-files", Status: StatusFail, Detail: strings.Join(problems, "; ")}
	}
	return CheckResult{Name: "attestation-files", Status: StatusPass, Detail: fmt.Sprintf("signatures.json matches %d signature block(s); %d .tsr file(s) match the manifest tokens", len(m.Signatures), len(m.Timestamps))}
}
