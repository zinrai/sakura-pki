package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
	"github.com/sacloud/sacloud-sdk-go/api/iaas/types"
)

type iaasID = types.ID

var issuanceURL = types.CertificateAuthorityIssuanceMethods.URL

func caCert(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID) (*x509.Certificate, error) {
	detail, err := api.Detail(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the CA certificate: %w", err)
	}
	if detail.CertificateData == nil || detail.CertificateData.CertificatePEM == "" {
		return nil, fmt.Errorf("the CA certificate was empty")
	}
	return parseCert(detail.CertificateData.CertificatePEM)
}

// The caller names the file rather than a layout of this tool's own, since it is
// installed by hand. 0644 because nothing written is secret. A temporary file
// renamed into place, so that a failure never leaves a server a truncated
// certificate.
func writePEM(path, pem string) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()

	if _, err := f.WriteString(pem); err != nil {
		return err
	}
	// CreateTemp makes the file 0600
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
