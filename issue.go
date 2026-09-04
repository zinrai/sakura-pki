package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
	"github.com/sacloud/sacloud-sdk-go/api/iaas/types"
)

// AddServer returns only an id, so the certificate is fetched separately.
// With the csr method it should be there at once, but the API does not say when.
const (
	pollInterval = 2 * time.Second
	pollTimeout  = 2 * time.Minute
)

type issueResult struct {
	ID             string
	CertificatePEM string
}

var errTimeout = errors.New("no certificate was issued")

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

	return i.wait(ctx, added.ID, func(ctx context.Context) (string, *iaas.CertificateData, error) {
		s, err := i.api.ReadServer(ctx, i.caID, added.ID)
		if err != nil {
			return "", nil, err
		}
		return s.IssueState, s.CertificateData, nil
	})
}

// wait judges by the certificate, not by IssueState.
//
// The API definition does not list the values IssueState can take. Matching on
// a state name would treat an issued certificate as a failure whenever a value
// we did not anticipate comes back.
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
			return nil, fmt.Errorf("%s: %w (IssueState=%q)", id, errTimeout, state)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(i.interval):
		}
	}
}
