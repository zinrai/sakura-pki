package main

import "testing"

// A miss issues a second live certificate for a name, which cannot be undone.
// A false hit blocks a name that is free.
func TestSubjectHasCN(t *testing.T) {
	cases := []struct {
		subject string
		cn      string
		want    bool
	}{
		{"CN=alice,OU=infra,O=Example Inc.,C=JP", "alice", true},
		{"CN=alice", "alice", true},
		{"O=Example Inc.,CN=alice", "alice", true},
		{"CN=alice2,O=Example Inc.", "alice", false},
		{"CN=2alice", "alice", false},
		{"O=alice,C=JP", "alice", false},
		{"CN=bob,O=Example Inc.", "alice", false},
		{"", "alice", false},
	}

	for _, c := range cases {
		if got := subjectHasCN(c.subject, c.cn); got != c.want {
			t.Errorf("subjectHasCN(%q, %q) = %v, want %v", c.subject, c.cn, got, c.want)
		}
	}
}
