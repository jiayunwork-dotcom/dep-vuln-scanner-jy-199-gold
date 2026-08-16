// Package sbom builds a minimal Software Bill of Materials document from a
// list of dependencies.
package sbom

import (
	"encoding/json"
	"strconv"

	"dep-vuln-scanner/internal/manifest"
)

// Component is one entry in the SBOM.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// Document is the top-level SBOM structure (CycloneDX-flavoured, simplified).
type Document struct {
	Metadata   map[string]string `json:"metadata"`
	Components []Component       `json:"components"`
}

// Generate builds an SBOM document from parsed dependencies.
func Generate(deps []manifest.Dependency) Document {
	comps := make([]Component, 0, len(deps))
	for _, d := range deps {
		comps = append(comps, Component{
			Name:    d.Name,
			Version: d.Version.String(),
			Type:    "library",
		})
	}
	return Document{
		Metadata: map[string]string{
			"schema": "sbom.example/v1",
			"tool":   "dep-vuln-scanner",
			"count":  strconv.Itoa(len(deps)),
		},
		Components: comps,
	}
}

// JSON serialises the document.
func (d Document) JSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
