package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

// freedStates are the states in which a certificate no longer holds its name.
// Anything else, including states this tool has not seen, is treated as still in
// use: issuing a second live certificate for a name cannot be undone, while a
// needless stop can be waved through with -force.
// pendingState is an enrolment URL that has been handed out but not used.
const pendingState = "approved"

var freedStates = map[string]bool{
	"revoked": true, // an issued certificate that was invalidated
	"denied":  true, // an enrolment URL that was cancelled before anyone used it
}

// cnInUse returns the live certificate holding cn, if any.
func cnInUse(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID, kind, cn string) (*certEntry, error) {
	certs, err := listCerts(ctx, api, id, kind)
	if err != nil {
		return nil, err
	}

	for _, c := range certs {
		if !freedStates[c.IssueState] && subjectHasCN(c.Subject, cn) {
			return &c, nil
		}
	}
	return nil, nil
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

// inUseError names the way out that fits the state it found. An enrolment that
// nobody has collected cannot be revoked, only denied, so pointing at revoke
// would send the reader down a path the CA rejects.
func inUseError(cn string, c *certEntry) error {
	way := "revoke it"
	if c.IssueState == pendingState {
		way = "deny it"
	}
	return fmt.Errorf("%s: a %s certificate is in the way (id=%s state=%s); %s or pass -force",
		cn, c.Kind, c.ID, c.IssueState, way)
}
