package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
	"github.com/sacloud/sacloud-sdk-go/api/iaas/types"
)

// iaasID is an alias so that a CA id and a certificate id are not swapped in an
// argument list. It is not there to hide the SDK type.
type iaasID = types.ID

const caCertName = "ca.crt"

// issuanceURL keeps the key in the user's browser. The csr and public_key
// methods would put a private key in the hands of whoever generated it, which
// is the thing a managed CA is meant to avoid.
var issuanceURL = types.CertificateAuthorityIssuanceMethods.URL

func writeCACert(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID, out string) error {
	detail, err := api.Detail(ctx, id)
	if err != nil {
		return fmt.Errorf("could not fetch the CA certificate: %w", err)
	}
	if detail.CertificateData == nil || detail.CertificateData.CertificatePEM == "" {
		return fmt.Errorf("the CA certificate was empty")
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, caCertName), []byte(detail.CertificateData.CertificatePEM), 0o644)
}

// writeCert writes with 0644 because everything this tool writes is public.
// No private key is generated, so there is nothing here to protect with 0600.
func writeCert(out, dir, name, certPEM string) (string, error) {
	d := filepath.Join(out, dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(d, name+".crt")
	return path, os.WriteFile(path, []byte(certPEM), 0o644)
}
