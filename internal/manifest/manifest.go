// Package manifest parses simple dependency lock files of the form:
//
//	module/path v1.2.3
//	another/module v0.4.0
//
// Blank lines and lines starting with '#' are ignored.
package manifest

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"dep-vuln-scanner/internal/semver"
)

// Dependency is a single name+version pair.
type Dependency struct {
	Name    string
	Version semver.Version
}

// Parse reads dependencies from r, one "name version" pair per line.
func Parse(r io.Reader) ([]Dependency, error) {
	var deps []Dependency
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("manifest: line %d: expected 'name version', got %q", lineNo, line)
		}
		v, err := semver.ParseVersion(fields[1])
		if err != nil {
			return nil, fmt.Errorf("manifest: line %d: %w", lineNo, err)
		}
		deps = append(deps, Dependency{Name: fields[0], Version: v})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return deps, nil
}
