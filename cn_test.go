package main

import (
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestLiveForLeavesOutExpiredAndFreedCertificates(t *testing.T) {
	certs := []certEntry{
		{ID: "expired", Subject: "CN=alice", IssueState: "available", Expired: true},
		{ID: "revoked", Subject: "CN=alice", IssueState: "revoked"},
		{ID: "denied", Subject: "CN=alice", IssueState: "denied"},
		{ID: "held", Subject: "CN=alice", IssueState: "hold"},
		{ID: "pending", Subject: "CN=alice", IssueState: "approved"},
		{ID: "current", Subject: "CN=alice", IssueState: "available"},
		{ID: "other", Subject: "CN=bob", IssueState: "available"},
	}

	var got []string
	for _, c := range liveFor(certs, "alice") {
		got = append(got, c.ID)
	}
	if want := "held pending current"; strings.Join(got, " ") != want {
		t.Errorf("live = %v, want %s", got, want)
	}
}

func TestHoldingLetsThroughOnlyWhatIsDueForRenewal(t *testing.T) {
	now := at("2026-06-01T00:00:00Z")
	year := func(id, notAfter string) certEntry {
		na := at(notAfter)
		return certEntry{ID: id, notBefore: na.AddDate(-1, 0, 0), notAfter: na}
	}

	cases := []struct {
		name string
		c    certEntry
		want bool
	}{
		{"far from expiry", year("a", "2026-12-01T00:00:00Z"), true},
		{"a day outside the window", year("b", "2026-07-02T00:00:00Z"), true},
		{"inside the window", year("c", "2026-06-20T00:00:00Z"), false},
		{"pending enrolment", certEntry{ID: "d", IssueState: "approved"}, true},
		{"a week-long certificate issued yesterday",
			certEntry{ID: "e", notBefore: now.AddDate(0, 0, -1), notAfter: now.AddDate(0, 0, 6)}, true},
	}
	for _, c := range cases {
		got := len(holding([]certEntry{c.c}, now)) == 1
		if got != c.want {
			t.Errorf("%s: holds = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSubjectHasCNMatchesWholeComponentsOnly(t *testing.T) {
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
