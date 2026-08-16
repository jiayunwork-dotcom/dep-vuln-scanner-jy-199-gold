package vulndb

import (
	"testing"

	"dep-vuln-scanner/internal/semver"
)

func TestVulnerabilities(t *testing.T) {
	db := DefaultDB()

	// 0.3.0 is in [0.3.0, 0.3.8) -> vulnerable.
	if got := db.Vulnerabilities("golang.org/x/text", semver.Version{Major: 0, Minor: 3, Patch: 0}); len(got) != 1 {
		t.Fatalf("x/text 0.3.0: want 1, got %d", len(got))
	}
	// 0.3.8 is the fixed version -> not vulnerable.
	if got := db.Vulnerabilities("golang.org/x/text", semver.Version{Major: 0, Minor: 3, Patch: 8}); len(got) != 0 {
		t.Fatalf("x/text 0.3.8: want 0, got %d", len(got))
	}
	// 0.4.0 is past the fixed version -> not vulnerable.
	if got := db.Vulnerabilities("golang.org/x/text", semver.Version{Major: 0, Minor: 4, Patch: 0}); len(got) != 0 {
		t.Fatalf("x/text 0.4.0: want 0, got %d", len(got))
	}
	// unscoped module -> no match.
	if got := db.Vulnerabilities("github.com/foo/bar", semver.Version{Major: 1, Minor: 0, Patch: 0}); len(got) != 0 {
		t.Fatalf("foo/bar: want 0, got %d", len(got))
	}
	// always-vulnerable demo lib.
	if got := db.Vulnerabilities("example.com/insecure-lib", semver.Version{Major: 9, Minor: 9, Patch: 9}); len(got) != 1 {
		t.Fatalf("insecure-lib: want 1, got %d", len(got))
	}
}

func TestFixedVersionBoundary(t *testing.T) {
	db := DefaultDB()
	// Fixed version itself must not be reported as vulnerable.
	if got := db.Vulnerabilities("golang.org/x/text", semver.Version{Major: 0, Minor: 3, Patch: 8}); len(got) != 0 {
		t.Fatalf("x/text 0.3.8 (fixed): want 0, got %d", len(got))
	}
}

func TestIntroducedInclusive(t *testing.T) {
	db := DefaultDB()
	// Version exactly equal to Introduced must be vulnerable.
	if got := db.Vulnerabilities("golang.org/x/text", semver.Version{Major: 0, Minor: 3, Patch: 0}); len(got) != 1 {
		t.Fatalf("x/text 0.3.0 (introduced): want 1, got %d", len(got))
	}
}
