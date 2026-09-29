package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
	"github.com/sacloud/sacloud-sdk-go/api/iaas/types"
)

// AddServer returns only an id and the certificate appears seconds later, so it
// is polled for. A CA that has not issued in 30 seconds is not working, and
// waiting longer only delays the error.
const (
	pollInterval = 2 * time.Second
	pollTimeout  = 30 * time.Second
)

type issueResult struct {
	ID             string
	CertificatePEM string
}

// Not "nothing was issued": the CA may still finish, and running the same
// command again picks the certificate up.
var errTimeout = errors.New("the CA had not issued the certificate")

type issuer struct {
	api      iaas.CertificateAuthorityAPI
	caID     types.ID
	interval time.Duration
	timeout  time.Duration
}

func newIssuer(api iaas.CertificateAuthorityAPI, caID types.ID) *issuer {
	return &issuer{api: api, caID: caID, interval: pollInterval, timeout: pollTimeout}
}

func (i *issuer) Server(ctx context.Context, param *iaas.CertificateAuthorityAddServerParam) (*issueResult, error) {
	added, err := i.api.AddServer(ctx, i.caID, param)
	if err != nil {
		return nil, fmt.Errorf("could not request issuance: %w", err)
	}

	return i.fetch(ctx, added.ID)
}

func (i *issuer) fetch(ctx context.Context, id string) (*issueResult, error) {
	return i.wait(ctx, id, func(ctx context.Context) (string, *iaas.CertificateData, error) {
		s, err := i.api.ReadServer(ctx, i.caID, id)
		if err != nil {
			return "", nil, err
		}
		return s.IssueState, s.CertificateData, nil
	})
}

// Judged by the certificate rather than IssueState, whose values the API does
// not list.
func (i *issuer) wait(ctx context.Context, id string, read func(context.Context) (string, *iaas.CertificateData, error)) (*issueResult, error) {
	deadline := time.Now().Add(i.timeout)
	var state string

	for {
		s, data, err := read(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: could not read the issue state: %w", id, err)
		}
		state = s
		if data != nil && data.CertificatePEM != "" {
			return &issueResult{ID: id, CertificatePEM: data.CertificatePEM}, nil
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("%w after %s (id=%s state=%s).\n"+
				"It may still be issued. Run the same command again to pick it up",
				errTimeout, i.timeout, id, state)
		}

		if err := sleep(ctx, i.interval); err != nil {
			return nil, err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
