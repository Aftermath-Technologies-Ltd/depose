// Package cmd, producer key catalog lookup for revocation checks.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func lookupRevocation(path, fingerprint string) (*keyCatalogEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cat keyCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, fmt.Errorf("malformed catalog JSON: %w", err)
	}
	if cat.SchemaVersion == 0 {
		return nil, fmt.Errorf("catalog is missing schemaVersion")
	}
	for i := range cat.Entries {
		if strings.EqualFold(cat.Entries[i].Fingerprint, fingerprint) {
			return &cat.Entries[i], nil
		}
	}
	return nil, nil
}
