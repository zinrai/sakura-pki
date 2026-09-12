# sakura-pki

Issue server and client certificates from SAKURA Cloud Managed PKI.

The tool never generates or writes a private key.

## Environment

Read from the environment. Either an API key or a service principal works. The
CA must already exist; its id goes here too, next to the credentials it belongs
to.

```
export SAKURACLOUD_ACCESS_TOKEN=...
export SAKURACLOUD_ACCESS_TOKEN_SECRET=...
export SAKURA_PKI_CA_ID=...
```

## Take the CA certificate

Both sides of a mutually authenticated connection need it. Nothing is issued,
so it can be run at any time.

```
sakura-pki ca -out ./out
```

This writes `out/ca.crt`.

## Issue a server certificate

Make the key and CSR on the server.

```
openssl req -new -newkey rsa:2048 -nodes \
  -keyout proxy.key -out proxy.csr -subj /CN=proxy.example.internal
```

Only the public key is taken from the CSR, so the `-subj` value does not matter.
Subject and SANs come from the flags below.

```
sakura-pki server -csr proxy.csr -out ./out \
  -country JP -org "Example Inc." \
  -san proxy.example.internal,localhost proxy.example.internal
```

This writes `out/server/proxy.example.internal.crt`. Leave `proxy.key` where
you made it.

`-san` entries become DNS names. An IP address is rejected: the API cannot
produce an iPAddress SAN. Reach such a host by name, or override the expected
name in the client.

## Issue client certificates

Same CA.

```
sakura-pki client -country JP -org "Example Inc." alice bob
```

One enrolment URL per user is printed. Hand it to that user. Nothing is
written to disk: the key and the certificate exist only in the user's browser.

```
[
  {
    "cn": "alice",
    "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "url": "https://pki.example/public/issue/client/<one-time-token>/"
  }
]
```

The user opens it, generates a key pair in the browser, and saves a PKCS#12 with
a passphrase of their choosing. The page works once, so a user who closes it
needs a new URL.

To get PEM out of the saved file. `-legacy` is needed because the PKCS#12 is
built with RC2-40 and 3DES, which OpenSSL 3 moved to its legacy provider:

```
openssl pkcs12 -legacy -in alice.p12 -clcerts -nokeys -out alice.crt
openssl pkcs12 -legacy -in alice.p12 -nocerts -nodes  -out alice.key
```

## What the server and the client need

The server:

- `out/server/<CN>.crt`
- `proxy.key`, still where you made it
- `out/ca.crt`, if it verifies client certificates

The client:

- `alice.crt` and `alice.key`, from the PKCS#12 they downloaded
- `out/ca.crt`

## Add a user later

```
sakura-pki client -country JP -org "Example Inc." carol
```

## List

```
$ sakura-pki list
[
  {
    "kind": "client",
    "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "issue_state": "approved",
    "subject": "CN=alice,O=Example Inc."
  },
  {
    "kind": "server",
    "id": "11111111-2222-3333-4444-555555555555",
    "issue_state": "available",
    "subject": "CN=proxy.example.internal,O=Example Inc."
  }
]
```

`issue_state` is `available` once issued, `approved` while an enrolment URL is
still waiting for its user, `revoked` after revocation and `denied` after a
pending enrolment was cancelled.

## Revoke and deny

Neither can be undone. Ids come from `list`.

```
sakura-pki revoke -client <ID>
sakura-pki revoke -server <ID>
```

An enrolment URL that nobody has used cannot be revoked. Cancel it instead.

```
sakura-pki deny <ID>
```

## Reissuing

Issuing never replaces. `server` and `client` stop when a live certificate for
the name already exists, and name it.

```
$ sakura-pki server -csr proxy.csr proxy.example.internal
proxy.example.internal: a server certificate is in the way
  (id=11111111-2222-3333-4444-555555555555 state=available); revoke it or pass -force
```

Nothing is written and nothing is issued. Revoke or deny the one it found, then
run again. `-force` issues anyway, and both certificates stay valid.

## Lifetime

`-ttl` defaults to 8760h.

## License

This project is licensed under the [MIT License](LICENSE).
