package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestListedCertReadsTheStateAndTheNestedExpiry(t *testing.T) {
	body := []byte(`{
	  "Total": 1,
	  "CertificateAuthority": [
	    {
	      "id": "aaaa-bbbb",
	      "subject": "CN=alice,O=Example Inc.",
	      "issue_state": "available",
	      "certificate_data": {
	        "serial_number": "0123456789",
	        "not_before": "2025-09-25T00:00:00+09:00",
	        "not_after": "2026-09-25T00:00:00+09:00"
	      }
	    }
	  ]
	}`)

	var page struct {
		Total                int
		CertificateAuthority []listedCert
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}

	got := page.CertificateAuthority[0].entry(clientKind, at("2026-01-01T00:00:00Z"))
	want := certEntry{
		Kind:         "client",
		ID:           "aaaa-bbbb",
		IssueState:   "available",
		Subject:      "CN=alice,O=Example Inc.",
		SerialNumber: "0123456789",
		NotAfter:     "2026-09-24T15:00:00Z",
		notBefore:    at("2025-09-24T15:00:00Z"),
		notAfter:     at("2026-09-24T15:00:00Z"),
	}
	if got != want {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestListedCertLeavesOutTheExpiryOfAPendingEnrolment(t *testing.T) {
	bodies := []string{
		`{"id":"cccc","subject":"CN=bob","issue_state":"approved"}`,
		`{"id":"cccc","subject":"CN=bob","issue_state":"approved","certificate_data":{}}`,
		`{"id":"cccc","subject":"CN=bob","issue_state":"approved","certificate_data":null}`,
	}

	for _, body := range bodies {
		var l listedCert
		if err := json.Unmarshal([]byte(body), &l); err != nil {
			t.Fatal(err)
		}
		if got := l.entry(clientKind, time.Now()); got.NotAfter != "" || got.Expired {
			t.Errorf("%s\n  want no expiry, got %q", body, got.NotAfter)
		}
	}
}

func TestListedCertMarksAnExpiredCertificate(t *testing.T) {
	var l listedCert
	body := `{"id":"aaaa","subject":"CN=alice","issue_state":"available",` +
		`"certificate_data":{"not_after":"2026-06-01T00:00:00Z"}}`
	if err := json.Unmarshal([]byte(body), &l); err != nil {
		t.Fatal(err)
	}

	if !l.entry(clientKind, at("2026-06-02T00:00:00Z")).Expired {
		t.Error("a certificate a day past its date is not expired")
	}
}

func TestPageThroughReadsEveryPageOfACappedListing(t *testing.T) {
	const total, capped = 25, 10
	var froms []int
	read := func(from int) ([]int, int, error) {
		froms = append(froms, from)
		var page []int
		for i := from; i < from+capped && i < total; i++ {
			page = append(page, i)
		}
		return page, total, nil
	}

	got, err := pageThrough(read)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != total {
		t.Fatalf("got %d items, want %d (read from %v)", len(got), total, froms)
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("item %d is %d, want every item once in order (read from %v)", i, v, froms)
		}
	}
}
