// Package semver provides a minimal semantic-version parser and comparator
// supporting the vMAJOR.MINOR.PATCH form used by most Go module versions.
package semver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed semantic version. A missing minor/patch defaults to 0.
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion parses strings like "v1.2.3", "1.2.3" or "1.2".
// A leading "v" is optional.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return Version{}, fmt.Errorf("semver: invalid version %q", s)
	}
	v := Version{}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("semver: invalid version %q: %w", s, err)
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, nil
}

// Compare returns -1 if v < o, 0 if equal, 1 if v > o.
func (v Version) Compare(o Version) int {
	for _, pair := range [3]struct{ a, b int }{
		{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch},
	} {
		if pair.a < pair.b {
			return -1
		}
		if pair.a > pair.b {
			return 1
		}
	}
	return 0
}

// IsZero reports whether the version is the zero value (unset).
func (v Version) IsZero() bool {
	return v.Major == 0 && v.Minor == 0 && v.Patch == 0
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
