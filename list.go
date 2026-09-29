package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

// Two commands rather than a filter, since the client certificates are the ones
// asked about. Entries keep their kind so that two listings can be merged.
func list(kind string, args []string) {
	fs := flag.NewFlagSet("list-"+kind, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: sakura-pki list-%s\n\n", kind)
		fmt.Fprintf(os.Stderr, "Print the %s certificates of this CA as JSON.\n", kind)
	}
	fs.Parse(args)

	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	api, id, _ := connect()

	certs, err := listCerts(context.Background(), api, id, kind)
	if err != nil {
		log.Fatal(err)
	}
	if certs == nil {
		certs = []certEntry{}
	}
	printJSON(certs)
}

// The API caps a page on its own, so even a large Count needs paging.
const pageSize = 100

// The expiry is flattened out because it ends a certificate for everyone, while
// a revocation counts only where the CRL is checked. A pending enrolment gets no
// date rather than a zero one. Expired is worked out here because the CA leaves
// an expired certificate available.
type certEntry struct {
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	IssueState   string `json:"issue_state"`
	Subject      string `json:"subject"`
	SerialNumber string `json:"serial_number,omitempty"`
	NotAfter     string `json:"not_after,omitempty"`
	Expired      bool   `json:"expired,omitempty"`

	notBefore time.Time
	notAfter  time.Time
}

// The tags are spelled out because Go would bind id without them but not
// issue_state, and an empty state makes a revoked certificate look live.
type listedCert struct {
	ID              string `json:"id"`
	Subject         string `json:"subject"`
	IssueState      string `json:"issue_state"`
	CertificateData *struct {
		SerialNumber string    `json:"serial_number"`
		NotBefore    time.Time `json:"not_before"`
		NotAfter     time.Time `json:"not_after"`
	} `json:"certificate_data"`
}

func (l listedCert) entry(kind string, now time.Time) certEntry {
	e := certEntry{Kind: kind, ID: l.ID, IssueState: l.IssueState, Subject: l.Subject}
	if d := l.CertificateData; d != nil {
		e.SerialNumber = d.SerialNumber
		e.notBefore = d.NotBefore.UTC()
		e.notAfter = d.NotAfter.UTC()
		if !d.NotAfter.IsZero() {
			e.NotAfter = e.notAfter.Format(time.RFC3339)
			e.Expired = !now.Before(d.NotAfter)
		}
	}
	return e
}

// Not the SDK's ListClients and ListServers, which send no paging, so the API
// returns ten and the check for a name in use misses the rest. Paging goes in
// the body of a GET, as the SDK's own FindCondition does it.
func listCerts(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID, kind string) ([]certEntry, error) {
	op, ok := api.(*iaas.CertificateAuthorityOp)
	if !ok {
		return nil, fmt.Errorf("unexpected API implementation %T", api)
	}
	url := fmt.Sprintf("%s/%s/%s/%s/%s/certificateauthority/%ss",
		iaas.SakuraCloudAPIRoot, iaas.APIDefaultZone, op.PathSuffix, op.PathName, id, kind)

	listed, err := pageThrough(func(from int) ([]listedCert, int, error) {
		data, err := op.Client.Do(ctx, "GET", url, map[string]any{"From": from, "Count": pageSize})
		if err != nil {
			return nil, 0, fmt.Errorf("could not list %s certificates: %w", kind, err)
		}

		var page struct {
			Total                int
			CertificateAuthority []listedCert
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, 0, fmt.Errorf("could not read the %s listing: %w", kind, err)
		}
		return page.CertificateAuthority, page.Total, nil
	})
	if err != nil {
		return nil, err
	}

	now := time.Now()
	out := make([]certEntry, 0, len(listed))
	for _, c := range listed {
		out = append(out, c.entry(kind, now))
	}
	return out, nil
}

// Apart from the request so that it can be tested without the SDK.
func pageThrough[T any](read func(from int) ([]T, int, error)) ([]T, error) {
	var out []T
	for {
		items, total, err := read(len(out))
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		// An empty page ends it even if Total never shrinks
		if len(items) == 0 || len(out) >= total {
			return out, nil
		}
	}
}
