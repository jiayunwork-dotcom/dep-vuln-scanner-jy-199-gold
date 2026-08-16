package manifest

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `# deps
github.com/foo/bar v1.2.3
example.com/baz 0.4.0

golang.org/x/text v0.3.0
`
	deps, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Fatalf("got %d deps, want 3", len(deps))
	}
	if deps[0].Name != "github.com/foo/bar" {
		t.Errorf("unexpected first name: %q", deps[0].Name)
	}
	if deps[0].Version.String() != "1.2.3" {
		t.Errorf("unexpected first version: %q", deps[0].Version)
	}
	if deps[2].Version.String() != "0.3.0" {
		t.Errorf("unexpected third version: %q", deps[2].Version)
	}
}

func TestParseBadLine(t *testing.T) {
	if _, err := Parse(strings.NewReader("onlyname")); err == nil {
		t.Error("expected error on malformed line")
	}
}

func TestParseRejectsExtraFields(t *testing.T) {
	if _, err := Parse(strings.NewReader("pkg v1.0.0 extra")); err == nil {
		t.Fatal("expected error when line has more than 2 fields")
	}
}

func TestParseSkipsHashComments(t *testing.T) {
	deps, err := Parse(strings.NewReader("# not a dep\ngithub.com/a/b v1.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1 (comment line must be skipped)", len(deps))
	}
}
