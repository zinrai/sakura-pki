package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sacloud/sacloud-sdk-go/api/iaas"
)

// pageSize is what we ask for per request. The API caps a page at some size of
// its own, which is why the result is still paged through rather than fetched in
// one go.
const pageSize = 100

// certEntry is the part of a listed certificate this tool uses.
//
// The tags are spelled out because the API sends snake_case. Go matches field
// names case insensitively, so id and subject would bind without them, but
// issue_state would not, and a silently empty state would make every revoked
// certificate look like it still holds its name.
type certEntry struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	IssueState string `json:"issue_state"`
	Subject    string `json:"subject"`
}

// listCerts pages through the clients or servers of a CA.
//
// It does not use the SDK's ListClients and ListServers because those send no
// request body, so the API applies its default page size of 10 and everything
// past the tenth certificate is silently dropped. That is not only a short
// listing: the check for a name that is already taken reads the same list, and
// would stop finding duplicates once a CA holds more than ten certificates.
//
// Paging parameters go in the body of a GET, the way the SDK's own FindCondition
// does it.
func listCerts(ctx context.Context, api iaas.CertificateAuthorityAPI, id iaasID, kind string) ([]certEntry, error) {
	op, ok := api.(*iaas.CertificateAuthorityOp)
	if !ok {
		return nil, fmt.Errorf("unexpected API implementation %T", api)
	}
	url := fmt.Sprintf("%s/%s/%s/%s/%s/certificateauthority/%s",
		iaas.SakuraCloudAPIRoot, iaas.APIDefaultZone, op.PathSuffix, op.PathName, id, kind)

	var out []certEntry
	for {
		data, err := op.Client.Do(ctx, "GET", url, map[string]any{"From": len(out), "Count": pageSize})
		if err != nil {
			return nil, fmt.Errorf("could not list %s certificates: %w", kind, err)
		}

		var page struct {
			Total                int
			CertificateAuthority []certEntry
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("could not read the %s listing: %w", kind, err)
		}

		for _, c := range page.CertificateAuthority {
			c.Kind = strings.TrimSuffix(kind, "s")
			out = append(out, c)
		}
		// An empty page ends the loop even if Total disagrees, so a Total that
		// never shrinks cannot spin here forever
		if len(page.CertificateAuthority) == 0 || len(out) >= page.Total {
			return out, nil
		}
	}
}
