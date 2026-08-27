# claim-signer

The Backend subsystem of the A10city Image Editor Generator Product, and the
only place a C2PA claim signing key exists.

```text
 browser (Edge)                          claim-signer (Backend)
 ────────────────                        ──────────────────────────────
 decode, edit, encode
 build claim + assertions
 Sig_structure    ────── TLS 1.3 ──────▶ authenticate the caller
 (~1 KB; no pixels)                      decrypt the key for one operation
                                         sign
                                         ask the TSA to stamp the signature
                  ◀───── signature ───── zeroise, log
                         + TimeStampToken
 assemble COSE_Sign1, embed
```

## Why it exists

Objective **O.2** of the C2PA Generator Product Security Requirements asks for a
claim signing key that is encrypted at rest, encrypted in memory except while
signing, access-controlled by least privilege, and rotatable. A key compiled
into a WebAssembly module and served to every visitor satisfies none of those,
so a browser-only claim generator cannot reach even Assurance Level 1.

Moving the *signature* off the client is the smallest change that fixes it. The
image is not sent: what crosses the wire is the `Sig_structure` — the claim, the
certificate chain and a context string — and it comes back with 64 bytes of
signature attached.

## Running it

```sh
export CLAIM_SIGNER_KEYSTORE=/var/lib/claim-signer
export CLAIM_SIGNER_KEK_FILE=/run/secrets/claim-signer-kek
export CLAIM_SIGNER_CLIENTS=/etc/claim-signer/clients.json
export CLAIM_SIGNER_TLS_CERT=/etc/claim-signer/tls.pem
export CLAIM_SIGNER_TLS_KEY=/etc/claim-signer/tls.key
export CLAIM_SIGNER_TSA_URL=https://ts.example.com/rfc3161

claim-signer serve
```

| Variable | Meaning |
|---|---|
| `CLAIM_SIGNER_BIND` | listen address, default `0.0.0.0:8443` |
| `CLAIM_SIGNER_KEYSTORE` | directory holding the sealed signing keys |
| `CLAIM_SIGNER_KEK_FILE` | file holding the key-encryption key, 32 Base64 bytes |
| `CLAIM_SIGNER_KEK` | the same, as an environment variable — the fallback, because `/proc` is readable |
| `CLAIM_SIGNER_CLIENTS` | JSON: `{ "<edge key id>": "<base64 secret ≥32 bytes>" }` |
| `CLAIM_SIGNER_TLS_CERT`, `CLAIM_SIGNER_TLS_KEY` | the server certificate and key |
| `CLAIM_SIGNER_CLIENT_CA` | optional: require mutual TLS against this CA bundle |
| `CLAIM_SIGNER_TSA_URL` | RFC 3161 endpoint; unset disables time-stamping |
| `CLAIM_SIGNER_TIMESTAMP_BUDGET` | bytes the Edge reserves for a token, default 12288 |
| `CLAIM_SIGNER_ALLOW_PLAINTEXT` | development only; logs a warning naming O.5 |

Every one of these fails the service closed if it is missing or wrong. A
key-encryption key that does not decrypt the active version, or a key that does
not match the certificate beside it, refuses to start — a mismatched deployment
should not come up and fail one user's save, it should not come up.

### Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | none | liveness, active key id, `notAfter`, whether time-stamping is on |
| `GET` | `/v1/identity` | none | the public credential: chain PEM, algorithm, key id, time-stamp budget, Assurance Level, CPL record id |
| `POST` | `/v1/sign` | HMAC | `{"toBeSigned": "<base64>"}` → `{"signature", "timestampToken"?, "keyId", "timestampError"?}` |

`/v1/identity` is unauthenticated because everything it returns is public, and
needing a credential to learn which certificate the service holds would make the
system harder to debug for no gain.

### Authenticating a caller

```text
Authorization: C2PA-HMAC-SHA256 key=<id>, ts=<unix>, nonce=<hex>, mac=<base64>

mac = HMAC-SHA256(secret,
        method ‖ "\n" ‖ path ‖ "\n" ‖ ts ‖ "\n" ‖ nonce ‖ "\n" ‖ hex(SHA-256(body)))
```

Symmetric key MAC is one of the methods O.2 names. It covers the request rather
than being a bearer token, so a captured header cannot be pointed at a different
claim. The timestamp must be within 120 seconds, nonces are remembered for that
window, and a failed attempt does not consume its nonce — otherwise an attacker
could burn one they had observed and the real request behind it would be
rejected as a replay.

Unknown key and bad MAC produce the same response, so the endpoint is not a way
to enumerate valid key ids. The log distinguishes them.

The browser gets its secret from the application server, minted per session and
short-lived. It is a rate and abuse control, which is exactly the role the
requirement scopes it to — "only for the purposes of limiting access to the
Backend subsystem" — and not a proof of identity. A browser cannot keep a
secret; the trust model rests on the key in this service, not on that one.

## The keystore

```text
keystore/
  active                   the id of the version to sign with
  2026-08-signer/
    key.enc                nonce ‖ AES-256-GCM(PKCS#8 DER), mode 0600
    chain.pem              x5chain: leaf first, trust anchor omitted
    meta.json              { "algorithm": "ES256", "importedAt": … }
```

The key-encryption key never lives on the same filesystem as the ciphertext, and
the ciphertext is bound to its version id as additional authenticated data — so
lifting a `key.enc` from a retired version into the active one fails to decrypt
rather than silently signing with the wrong key.

The plaintext exists inside `Keystore::sign` and nowhere else, in a buffer that
zeroes on drop. There is no accessor that hands the key to a caller, because a
key you cannot get hold of cannot be leaked by the next person to add a feature.

### Rotation

```sh
claim-signer import   --id 2027-01-signer --key new.key --chain new.pem
claim-signer activate --id 2027-01-signer   # then restart
claim-signer versions                       # '*' marks the active one
```

Two commands, deliberately: a new credential can be staged and inspected while
the old one is still signing. Retired versions stay — images signed under them
are still in the world.

The Edge notices a rotation mid-export and retries rather than shipping a
signature that does not match the certificate already committed to in the
manifest.

## Time-stamping

An Assurance Level 1 certificate lasts at most 366 days, and §15.8 judges an
untimestamped manifest against the validity window *at the moment someone looks
at it*. Without a time-stamp, every image the editor has ever signed stops
validating on the certificate's anniversary. With one, a validator judges the
certificate at the attested time instead.

The service asks the TSA for a stamp over the signature — a 32-byte digest
crosses that hop, nothing else — and returns it. Where the authority is
unreachable, the response says so, the file is still written, and the interface
passes the reason on. Refusing to save someone's photograph because a third
party was down would be the wrong trade.

The token is checked before it is returned: it must parse, its imprint must
cover the signature that was sent, and it must carry the TSA's certificate. A
stamp over the wrong bytes would otherwise be embedded, shipped, and noticed
only by someone else's validator.

## Deploying it

Objective **O.6** covers the hosting environment, and it is a property of the
deployment rather than of this code. What must be in place, and what an assessor
will ask to see, is set out in
`conformance/generator-product-security-architecture.md` §2.6. In summary:

- a single-purpose project whose only workload is claim signing
- three IAM roles — runtime, operator, auditor — and no principal holding both
  operator and control of the audit log destination
- the key-encryption key in the provider's secret manager, readable by the
  runtime identity alone
- the container running as an unprivileged account with no shell
- weekly base-image rebuilds, and on any advisory affecting it
- 30/90/180-day remediation for High/Moderate/Low findings

The service logs one structured JSON record per signature — the client, the key
id, a digest of the signature, and whether it was time-stamped — and one per
refusal with its reason. The claim itself is never logged.

## Testing

```sh
cargo test -p claim-signer
```

Twenty-five tests. The ones worth knowing about assert properties rather than
behaviour: that the plaintext key never appears in `key.enc`, that a sealed key
moved between versions does not decrypt, that a key which does not match its
certificate stops the service starting, that a replayed request is refused and a
forged one does not consume its nonce, and that the TSA request carries a digest
and not the signature.

Those test the code. Testing a *deployment* — that this service, on this host,
with this certificate, produces credentials someone else's validator accepts —
is [`TESTING.md`](TESTING.md), which covers both a local run on the test PKI and
a production one on an SSL.com credential. `scripts/smoke-test.sh` exercises a
running service, including the refusals:

```sh
./services/claim-signer/scripts/smoke-test.sh \
    --url https://sign.example.com --key-id "$KEY_ID" --secret "$SECRET"
```
