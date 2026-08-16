package semver

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want Version
	}{
		{"v1.2.3", Version{Major: 1, Minor: 2, Patch: 3}},
		{"1.2.3", Version{Major: 1, Minor: 2, Patch: 3}},
		{"2.0", Version{Major: 2, Minor: 0, Patch: 0}},
		{"0.0.1", Version{Major: 0, Minor: 0, Patch: 1}},
	}
	for _, c := range cases {
		got, err := ParseVersion(c.in)
		if err != nil {
			t.Fatalf("ParseVersion(%q) error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseVersion(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	if _, err := ParseVersion("nope"); err == nil {
		t.Error("expected error for non-numeric version")
	}
}

func TestCompare(t *testing.T) {
	a, _ := ParseVersion("1.2.3")
	b, _ := ParseVersion("1.3.0")
	c, _ := ParseVersion("1.2.3")
	if a.Compare(b) != -1 {
		t.Error("1.2.3 should be < 1.3.0")
	}
	if b.Compare(a) != 1 {
		t.Error("1.3.0 should be > 1.2.3")
	}
	if a.Compare(c) != 0 {
		t.Error("1.2.3 should equal 1.2.3")
	}
}

func TestParseVersionLeadingV(t *testing.T) {
	got, err := ParseVersion("v1.2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := Version{Major: 1, Minor: 2, Patch: 3}
	if got != want {
		t.Fatalf("got %v want %v", got, want)
	}
}
