// internal/govuln.go
package internal

import (
	"encoding/json"
	"fmt"
)

// Govuln holds the parsed vulnerabilities from govulncheck output
type Govuln struct {
	Vulnerabilities []VulnEntry
}

// VulnEntry represents an individual vulnerability (OSV record) with its ID
type VulnEntry struct {
	ID string
}

// ParseGovulnJSON unmarshals govuln.json, which is an array of heterogeneous
// objects, extracting only the OSV entries into Govuln.Vulnerabilities
func ParseGovulnJSON(data []byte) (Govuln, error) {
	// The govulncheck JSON comes as a top-level array
	var rawEntries []map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawEntries); err != nil {
		return Govuln{}, fmt.Errorf("invalid govuln.json format: %w", err)
	}

	var result Govuln
	// Iterate through each element and look for the "osv" key
	for _, entry := range rawEntries {
		if osvRaw, ok := entry["osv"]; ok {
			// We only care about the ID field
			var osv struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(osvRaw, &osv); err != nil {
				// Skip entries we can’t parse
				continue
			}
			result.Vulnerabilities = append(result.Vulnerabilities, VulnEntry{ID: osv.ID})
		}
	}
	return result, nil
}
