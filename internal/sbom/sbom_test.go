package sbom

import (
	"dep-vuln-scanner/internal/manifest"
	"dep-vuln-scanner/internal/semver"
	"testing"
)

func TestGenerate(t *testing.T) {
	deps := []manifest.Dependency{
		{Name: "a/b", Version: semver.Version{Major: 1, Minor: 0, Patch: 0}},
		{Name: "c/d", Version: semver.Version{Major: 2, Minor: 3, Patch: 4}},
	}
	doc := Generate(deps)
	if len(doc.Components) != 2 {
		t.Fatalf("want 2 components, got %d", len(doc.Components))
	}
	if doc.Components[1].Version != "2.3.4" {
		t.Errorf("unexpected version %q", doc.Components[1].Version)
	}
	b, err := doc.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Error("empty JSON")
	}
}

func TestGenerateMetadataCount(t *testing.T) {
	deps := []manifest.Dependency{
		{Name: "a/b", Version: semver.Version{Major: 1, Minor: 0, Patch: 0}},
		{Name: "c/d", Version: semver.Version{Major: 2, Minor: 0, Patch: 0}},
	}
	doc := Generate(deps)
	if doc.Metadata["count"] != "2" {
		t.Fatalf("metadata count = %q, want \"2\"", doc.Metadata["count"])
	}
	if doc.Components[0].Type != "library" {
		t.Fatalf("type = %q, want library", doc.Components[0].Type)
	}
}
