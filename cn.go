package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

// An unknown state holds the name rather than freeing it: a needless stop is
// cheaper than a certificate nobody needed.
var freedStates = map[string]bool{
	"revoked": true, // an issued certificate that was invalidated
	"denied":  true, // an enrolment URL that was cancelled before anyone used it
}

// approved is the API's name for an enrolment URL nobody has used yet.
const pendingState = "approved"

// Renewal issues beside the old certificate rather than revoking it first, so
// there is time to install the new one. Weeks rather than hours, because a
// client may take days to open the enrolment URL.
const renewWithin = 30 * 24 * time.Hour

// Without it, a certificate shorter-lived than renewWithin is due at once and
// every roster run issues it again.
const renewFraction = 3

func liveCerts(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID, kind, cn string) ([]certEntry, error) {
	certs, err := listCerts(ctx, api, id, kind)
	if err != nil {
		return nil, err
	}
	return liveFor(certs, cn), nil
}

// Decided by date rather than state, since the CA leaves an expired certificate
// available.
func liveFor(certs []certEntry, cn string) []certEntry {
	var out []certEntry
	for _, c := range certs {
		if !freedStates[c.IssueState] && !c.Expired && subjectHasCN(c.Subject, cn) {
			out = append(out, c)
		}
	}
	return out
}

func holding(live []certEntry, now time.Time) []certEntry {
	var out []certEntry
	for _, c := range live {
		if !c.due(now) {
			out = append(out, c)
		}
	}
	return out
}

func (c certEntry) due(now time.Time) bool {
	// Nothing issued yet is not due, or every run would send another URL
	if c.notAfter.IsZero() {
		return false
	}
	window := renewWithin
	if third := c.notAfter.Sub(c.notBefore) / renewFraction; third < window {
		window = third
	}
	return !c.notAfter.After(now.Add(window))
}

func describe(c certEntry) string {
	if c.NotAfter == "" {
		return fmt.Sprintf("id=%s state=%s", c.ID, c.IssueState)
	}
	return fmt.Sprintf("id=%s state=%s not_after=%s", c.ID, c.IssueState, c.NotAfter)
}

// subjectHasCN compares whole components rather than looking for a substring,
// so that CN=alice does not match a certificate issued to CN=alice2.
func subjectHasCN(subject, cn string) bool {
	for _, part := range strings.Split(subject, ",") {
		if strings.TrimSpace(part) == "CN="+cn {
			return true
		}
	}
	return false
}
