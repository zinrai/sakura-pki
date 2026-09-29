# sakura-pki

Issue server and client certificates from SAKURA Cloud Managed PKI.

The tool never generates or writes a private key.

## Commands

```
sakura-pki list-ca        list the CAs in this account with their fingerprints
sakura-pki get-ca         write the CA certificate to a file
sakura-pki issue-client   issue an enrolment URL per user
sakura-pki issue-server   issue a certificate for a CSR
sakura-pki revoke-client  revoke a client certificate
sakura-pki revoke-server  revoke a server certificate
sakura-pki deny-client    cancel an enrolment URL that was never used
sakura-pki list-client    list client certificates and enrolments
sakura-pki list-server    list server certificates
sakura-pki version        print version and exit
```

Every command prints the CA it reached on stderr:

```
CA: example-ca (Example Client CA, id=123456789012)
```

## Environment

Either an API key or a service principal works. The CA must already exist, and
is named by the SHA-256 fingerprint of its certificate.

```
export SAKURACLOUD_ACCESS_TOKEN=...
export SAKURACLOUD_ACCESS_TOKEN_SECRET=...
export SAKURA_PKI_CA_FINGERPRINT=...
```

A fingerprint that no CA in the account has stops every command.

## Find the CA

`list-ca` needs only the credentials. Record the fingerprint of the CA you
mean, and set it wherever the tool is run.

```
$ sakura-pki list-ca
[
  {
    "id": "123456789012",
    "name": "example-ca",
    "subject": "CN=Example Client CA,O=Example Inc.,C=JP",
    "not_after": "2035-01-01T00:00:00Z",
    "fingerprint_sha256": "AA:BB:CC:..."
  }
]
```

## Take the CA certificate

Both sides of a mutually authenticated connection need it. Nothing is issued,
so it can be run at any time.

```
$ sakura-pki get-ca -out ca.crt
{
  "ca_certificate": "ca.crt",
  "subject": "CN=Example Client CA,O=Example Inc.,C=JP",
  "not_after": "2035-01-01T00:00:00Z",
  "fingerprint_sha256": "AA:BB:CC:..."
}
```

The fingerprint is printed the way `openssl x509 -fingerprint -sha256` prints
it, so it can be compared against a copy that has already reached a host.

## Issue a server certificate

Make the key and CSR on the server.

```
openssl req -new -newkey rsa:2048 -nodes \
  -keyout proxy.key -out proxy.csr -subj /CN=proxy.example.internal
```

```
$ sakura-pki issue-server -csr proxy.csr
{
  "cn": "proxy.example.internal",
  "id": "11111111-2222-3333-4444-555555555555",
  "certificate": "proxy.example.internal.crt",
  "subject": "CN=proxy.example.internal,O=Example Inc.,C=JP",
  "sans": ["proxy.example.internal"],
  "not_after": "2026-09-25T00:00:00Z",
  "fingerprint_sha256": "11:22:33:..."
}
```

Leave `proxy.key` where you made it.

The common name comes from the CSR. `-cn` is for a CSR that has no common name,
or one whose name is not the one to issue under. The country and organisation
come from the CA's own certificate.

`-out` names the file. It defaults to `<CN>.crt` in the current directory.

`-san` adds DNS names on top of the CN, which is always included. IP addresses
are rejected, so reach such a host by name.

The certificate is written only once it holds the CSR's public key and every
name that was asked for.

## Issue client certificates

```
$ sakura-pki issue-client -cn alice
{
  "cn": "alice",
  "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "url": "https://pki.example/public/issue/client/<one-time-token>/"
}
```

Hand the URL to that user. Nothing is written to disk.

The user opens it, generates a key pair in the browser, and saves a PKCS#12 with
a passphrase of their choosing. The page works once, so a user who closes it
needs a new URL.

To get PEM out of the saved file. `-legacy` is needed because the PKCS#12 is
built with RC2-40 and 3DES, which OpenSSL 3 moved to its legacy provider:

```
openssl pkcs12 -legacy -in alice.p12 -clcerts -nokeys -out alice.crt
openssl pkcs12 -legacy -in alice.p12 -nocerts -nodes  -out alice.key
```

## Issue for a list of people

A name that already has a certificate is reported and left alone, so the same
list can be run through as often as it changes.

```
$ while read -r cn; do sakura-pki issue-client -cn "$cn"; done < roster.txt > urls.json
CA: example-ca (Example Client CA, id=123456789012)
alice: already has a client certificate (id=aaaa state=available not_after=2027-03-01T00:00:00Z)
CA: example-ca (Example Client CA, id=123456789012)
bob: an enrolment URL is waiting to be used (id=bbbb state=approved)
CA: example-ca (Example Client CA, id=123456789012)
carol: renewing, the current certificate is left to expire (id=cccc state=available not_after=2026-10-10T00:00:00Z)
CA: example-ca (Example Client CA, id=123456789012)
```

Only what was issued reaches stdout, one JSON object per enrolment URL, so what
a run captures is the enrolment URLs and nothing else.

The same run renews. See [Renewal](#renewal).

## What the server and the client need

The server:

- `proxy.example.internal.crt`
- `proxy.key`, still where you made it
- `ca.crt`, if it verifies client certificates

The client:

- `alice.crt` and `alice.key`, from the PKCS#12 they downloaded
- `ca.crt`

## Renewal

Issuing for a name that already has a certificate stops, unless that
certificate has 30 days or a third of its lifetime left, whichever is shorter.
Then a new one is issued beside it, and the old one is left to run out on its
date.

For a client, running the roster is the renewal. For a server, run
`issue-server` again. The CSR may be new or the one used before.

Outside that window, issuing stops and names the command that clears the way:

```
$ sakura-pki issue-server -csr proxy.csr
proxy.example.internal: a server certificate is in the way (id=1111 state=available
  not_after=2027-09-25T00:00:00Z). To replace it, run
  sakura-pki revoke-server -cn proxy.example.internal
```

Nothing is written and nothing is issued.

### When issue-server stops waiting

`issue-server` waits 30 seconds for the CA. If it gives up, the CA may still
finish. Run the same command again with the same CSR, and the certificate is
written out instead of a new one being issued.

## Revoke and deny

Revoking cannot be undone. It takes the name the certificate was issued to, and
revokes every live certificate with that name. `revoke-client` also cancels any
enrolment URL for the name that nobody has used.

```
sakura-pki revoke-client -cn alice
sakura-pki revoke-server -cn proxy.example.internal
```

`deny-client` cancels only the enrolment URLs that have not been used, and
leaves a certificate the name already has alone. Use it to withdraw a renewal
without taking away the certificate still in use.

```
sakura-pki deny-client -cn alice
```

### A user lost a device

Revoke, then issue. Once revoked, the name has no certificate, so the next
`issue-client` gives it a new enrolment URL.

```
sakura-pki revoke-client -cn alice
sakura-pki issue-client -cn alice
```

## List

```
$ sakura-pki list-client
[
  {
    "kind": "client",
    "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "issue_state": "available",
    "subject": "CN=alice,O=Example Inc.",
    "serial_number": "0123456789",
    "not_after": "2026-09-25T00:00:00Z"
  },
  {
    "kind": "client",
    "id": "cccccccc-...",
    "issue_state": "approved",
    "subject": "CN=bob,O=Example Inc."
  }
]
```

`issue_state` is `available` once issued, `approved` while an enrolment URL is
still waiting for its user, `hold` while suspended, `revoked` after revocation
and `denied` after a pending enrolment was cancelled. An enrolment nobody has
collected has no serial number and no expiry. A certificate past its date stays
`available` and carries `"expired": true`.

## Lifetime

`-days` defaults to 365.

## License

This project is licensed under the [MIT License](LICENSE).
