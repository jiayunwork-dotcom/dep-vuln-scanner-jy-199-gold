// Package vulndb holds a small built-in vulnerability database and the
// matching logic that decides whether a given module version is affected.
package vulndb

import (
	"dep-vuln-scanner/internal/semver"
)

// AffectedRange describes a vulnerable window. A version v is affected when
// v >= Introduced and (Fixed is unset or v < Fixed).
type AffectedRange struct {
	Introduced semver.Version
	Fixed      semver.Version // zero value means "no known fix / all >= Introduced"
}

// Entry is a single vulnerability record for one module.
type Entry struct {
	Module   string
	Ranges   []AffectedRange
	ID       string // e.g. CVE-2024-0001
	Severity string // low | moderate | high | critical
	Summary  string
}

// DB is a collection of vulnerability entries.
type DB struct {
	Entries []Entry
}

// Vulnerabilities returns all entries that affect (module, version).
func (db DB) Vulnerabilities(module string, version semver.Version) []Entry {
	var out []Entry
	for _, e := range db.Entries {
		if e.Module != module {
			continue
		}
		for _, r := range e.Ranges {
			intro := version.Compare(r.Introduced) >= 0
			safe := !r.Fixed.IsZero() && version.Compare(r.Fixed) >= 0
			if intro && !safe {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// DefaultDB returns a small illustrative database used when no external
// database file is supplied.
func DefaultDB() DB {
	return DB{Entries: []Entry{
		{
			Module:   "golang.org/x/text",
			Ranges:   []AffectedRange{{Introduced: semver.Version{Major: 0, Minor: 3, Patch: 0}, Fixed: semver.Version{Major: 0, Minor: 3, Patch: 8}}},
			ID:       "CVE-2023-39418",
			Severity: "high",
			Summary:  "language tags denial of service",
		},
		{
			Module:   "github.com/docker/distribution",
			Ranges:   []AffectedRange{{Introduced: semver.Version{Major: 2, Minor: 7, Patch: 0}, Fixed: semver.Version{Major: 2, Minor: 8, Patch: 0}}},
			ID:       "CVE-2024-1234",
			Severity: "critical",
			Summary:  "manifest injection via crafted tag",
		},
		{
			Module:   "example.com/insecure-lib",
			Ranges:   []AffectedRange{{Introduced: semver.Version{Major: 0, Minor: 0, Patch: 0}}},
			ID:       "CVE-2022-9999",
			Severity: "moderate",
			Summary:  "always-vulnerable reference library (demo)",
		},
	}}
}
