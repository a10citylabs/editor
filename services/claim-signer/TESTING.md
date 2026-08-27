# Testing the Backend subsystem

Three layers, and they fail in different ways, so they are tested separately:

| Layer | What it answers | Needs |
|---|---|---|
| The crate's own tests | does the key stay sealed, does authentication hold | nothing |
| The running service | does *this* deployment answer correctly | a URL and a client secret |
| The whole path | does a browser produce a credential someone else's validator accepts | the editor and a validator |

Locally all three run against the test PKI in `conformance/test-credentials/`.
In production they run against the certificate SSL.com issued and the
time-stamping authority that came with it. The commands are almost the same;
what changes is what the answers are allowed to be.

None of this needs access to the signing key, which is the point — every check
here is one an auditor could repeat without being trusted with anything.

---

## Part 1 — Locally, on the test PKI

### 1. The crate's tests

```sh
cargo test -p claim-signer     # 25 tests
cargo test --workspace         # the engine and the validator too
```

The ones worth knowing about assert properties rather than behaviour: that the
plaintext key never appears in `key.enc`, that a sealed key moved between
versions does not decrypt, that a key which does not match its certificate stops
the service starting, that a replayed request is refused and a forged one does
not consume its nonce, and that the TSA request carries a digest and not the
signature.

They do not test a *deployment*, which is what the rest of this document is for.

### 2. Bring a service up

```sh
cargo build -p claim-signer

mkdir -p /var/tmp/cs/keystore
head -c 32 /dev/urandom | base64 > /var/tmp/cs/kek.b64
printf '{"dev":"%s"}\n' "$(head -c 32 /dev/urandom | base64)" > /var/tmp/cs/clients.json
chmod 600 /var/tmp/cs/kek.b64 /var/tmp/cs/clients.json

export CLAIM_SIGNER_KEYSTORE=/var/tmp/cs/keystore
export CLAIM_SIGNER_KEK_FILE=/var/tmp/cs/kek.b64
export CLAIM_SIGNER_CLIENTS=/var/tmp/cs/clients.json

./target/debug/claim-signer import --id dev \
    --key   conformance/test-credentials/c2pa-test-claim-signer.key \
    --chain conformance/test-credentials/c2pa-test-claim-signer-chain.pem
./target/debug/claim-signer activate --id dev
./target/debug/claim-signer versions          # '*' marks the active one

CLAIM_SIGNER_BIND=127.0.0.1:8443 CLAIM_SIGNER_ALLOW_PLAINTEXT=1 \
    ./target/debug/claim-signer serve
```

The start-up line is itself a test. It reports what the active certificate
claims, and on the test PKI it should say `assurance_level: Some(1)`,
`claim_signing_eku: true`, `kek_source: file`:

```json
{"level":"INFO","fields":{"message":"claim-signer starting","key_id":"dev",
 "algorithm":"ES256","subject":"C = IN, O = A10city Labs, CN = A10city Image Editor",
 "assurance_level":"Some(1)","claim_signing_eku":true,"kek_source":"file",
 "clients":1,"tsa":"none"}}
```

`CLAIM_SIGNER_ALLOW_PLAINTEXT` also logs a warning naming objective O.5 every
time it starts. That warning is correct and should never be silenced — see §5
for running the TLS listener instead.

**Check that it fails closed**, because a service that comes up
half-configured is the failure this design exists to prevent. Each of these
should refuse to start rather than start and misbehave:

| Change | Expected |
|---|---|
| unset `CLAIM_SIGNER_KEK_FILE` and `CLAIM_SIGNER_KEK` | `no key-encryption key: set CLAIM_SIGNER_KEK_FILE (preferred) or CLAIM_SIGNER_KEK to 32 Base64-encoded bytes` |
| a 16-byte KEK | `the key-encryption key must be 32 bytes, not 16` |
| a different KEK than the one the key was sealed under | decryption fails; the service does not start |
| copy `key.enc` from one version directory into another | fails to decrypt — the ciphertext is bound to its version id |
| a secret shorter than 32 bytes in `clients.json` | `the secret for 'dev' is N bytes; at least 32 are required` |
| a TLS certificate and key that do not match | `the TLS certificate and key do not go together` |

### 3. Smoke-test the API

Signing by hand is awkward — the request is authenticated with an HMAC over the
method, path, timestamp, nonce and a digest of the body, so `curl` alone cannot
do it. The script does:

```sh
SECRET=$(python3 -c 'import json;print(json.load(open("/var/tmp/cs/clients.json"))["dev"])')

./services/claim-signer/scripts/smoke-test.sh \
    --url http://127.0.0.1:8443 --key-id dev --secret "$SECRET"
```

```text
Public endpoints
  ok   GET /healthz — keyId:dev,notAfter:…,status:ok,timeStamping:false
  ok   GET /v1/identity — keyId=dev algorithm=ES256 notAfter=…
  ok     certificate carries C2PA Assurance Level 1, CPL record 0000…

Signing
  ok   POST /v1/sign — signed

Refusals
  ok   no Authorization header → 401
  ok   replayed nonce → 401
  ok   timestamp outside the window → 401
  ok   unknown key id → 401
```

The refusals are the half of the test that matters. A signing endpoint that
signs is unremarkable; one that also refuses a replayed request, a stale one and
an unknown key id is the one the requirement asks for. Note that unknown key and
bad MAC answer identically — that is deliberate, so the endpoint cannot be used
to enumerate key ids. The log distinguishes them:

```sh
grep 'refused a signing request' service.log     # reason=… names which it was
grep 'signed a claim' service.log                # client, key id, digest, time_stamped
```

The claim itself is never logged, so there is nothing in there to redact.

### 4. Time-stamping

There is no local authority to test against, so point the service at a real one.
SSL.com's C2PA endpoint answers unauthenticated queries, which makes it usable
as a test target before any certificate has been issued:

```sh
export CLAIM_SIGNER_TSA_URL=https://api.c2patool.io/api/v1/timestamps/ecc
```

Isolate the authority from the service first, so a failure has one meaning:

```sh
echo test > /tmp/data.bin
openssl ts -query -data /tmp/data.bin -sha256 -cert -out /tmp/req.tsq
curl -s -H 'Content-Type: application/timestamp-query' \
     --data-binary @/tmp/req.tsq \
     https://api.c2patool.io/api/v1/timestamps/ecc -o /tmp/resp.tsr
openssl ts -reply -in /tmp/resp.tsr -text | head -20
```

Expect `Status: Granted`, `Policy OID: 1.3.6.1.4.1.62558.1.1` — the C2PA policy
— and a TSA of `CN = SSL.com C2PA TSA SUB E1`. (Checked 27 August 2026.)

Then restart the service with `CLAIM_SIGNER_TSA_URL` set: `/healthz` should
report `"timeStamping":true`, and the smoke test's signing line should say
*signed and time-stamped* rather than *signed*.

If it instead reports a `timestampError`, read it before assuming the authority
is down. The service degrading rather than failing is the designed behaviour —
refusing to save someone's photograph because a third party was unreachable
would be the wrong trade — so a broken configuration looks like a working one
unless the error is read. In particular:

```text
the time-stamping authority could not be reached: … invalid peer certificate: UnknownIssuer
```

means the *host* does not trust the authority's chain. The TSA client trusts a
compiled-in Mozilla root set (`webpki-roots`), not the operating system's store,
so a TLS-intercepting egress proxy breaks this leg while leaving `curl` working.

### 5. The TLS listener

`CLAIM_SIGNER_ALLOW_PLAINTEXT` is a development escape hatch; the listener the
product actually deploys is TLS 1.3 only. Exercise it locally with a self-signed
certificate:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout /var/tmp/cs/tls.key -out /var/tmp/cs/tls.pem -days 30 \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'

CLAIM_SIGNER_TLS_CERT=/var/tmp/cs/tls.pem \
CLAIM_SIGNER_TLS_KEY=/var/tmp/cs/tls.key \
CLAIM_SIGNER_BIND=127.0.0.1:8443 ./target/debug/claim-signer serve
```

It should log `listening with TLS 1.3`, and then:

```sh
echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 | grep -E 'Protocol|Cipher'
#   New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384

echo | openssl s_client -connect 127.0.0.1:8443 -tls1_2
#   …alert protocol version… — TLS 1.2 is refused, not merely discouraged
```

The second check is the one worth keeping: O.5 asks for TLS 1.3, and the
listener is configured with it as the *only* permitted version, so a downgrade
is impossible rather than deprecated. Add `--insecure` to the smoke test to run
it against a self-signed listener.

### 6. End to end, through the browser

```sh
npm run dev
```

and put a `claim-signer.json` in `apps/editor/public/` (git-ignored, because it
carries a secret):

```json
{
  "url": "/signer",
  "credential": { "keyId": "dev", "secret": "<the same Base64 secret>" }
}
```

**`"/signer"`, not `"http://localhost:8443"`.** Two things make the direct URL
fail, and both have production counterparts:

- The service serves no CORS headers — preflight `OPTIONS /v1/sign` answers 405
  and `/v1/identity` carries no `Access-Control-Allow-Origin` — so a page on
  `:5173` cannot call `:8443` at all. The deployment it is written for puts the
  Edge and the Backend behind one origin.
- The Edge computes its request MAC over the literal path `/v1/sign`, and the
  service recomputes it over the path it receives. Any proxy in between has to
  **strip its prefix**, or every signature is refused while `/v1/identity`
  keeps working — a confusing failure that looks like a bad secret.

The dev server's proxy (in `apps/editor/vite.config.ts`) does both: `/signer/*`
is forwarded to `CLAIM_SIGNER_ORIGIN`, default `http://127.0.0.1:8443`, with the
prefix removed. You can confirm the same rewrite a production proxy needs by
pointing the smoke test through it:

```sh
./services/claim-signer/scripts/smoke-test.sh \
    --url http://127.0.0.1:5173/signer --key-id dev --secret "$SECRET"
```

Then in the browser: open a JPEG, check that **Content Credentials** offers to
sign, export, and validate what came out.

```sh
cargo build --release -p c2pa-harness
./target/release/c2pa-harness validate \
    --asset ~/Downloads/photo-edited.jpg \
    --trust-list     conformance/test-credentials/c2pa-test-trust-list.pem \
    --tsa-trust-list conformance/test-credentials/c2pa-test-tsa-trust-list.pem \
    --validation-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --summary
```

Expect `claimSignature.validated`, `assertion.dataHash.match` and
`signingCredential.trusted`. Cross-check with an implementation that is not this
one, because agreeing with yourself proves nothing:

```sh
cargo install c2patool
c2patool ~/Downloads/photo-edited.jpg          # "validation_state": "Valid"
```

Without the browser, `./conformance/scripts/generate-evidence.sh` signs sample
assets with the same test PKI and validates them, which exercises the manifest
path but not the service.

---

## Part 2 — In production, on the SSL.com credential

### What SSL.com issues

Their [C2PA offering](https://www.ssl.com/products/content-authenticity/content-credentials/c2pa/)
has a free tier — one Assurance Level 1 claim signing certificate valid for a
year, and 10,000 trusted time-stamps annually, issued through the portal — and a
premium tier adding unlimited AL1 certificates, AL2, device certificates and API
issuance. **The free tier requires a valid C2PA conformance record id**, so
steps 1–3 of `conformance/enrolment-runbook.md` come first: the certificate
cannot be requested until the Conforming Products List record exists.

Issuance is CSR-based with organization validation. Generate the key on the
Backend host so it never travels — `conformance/enrolment-runbook.md` §4 has the
exact commands and the subject-name rule.

### 1. Check the certificate before importing

The service refuses to start on a key that does not match its certificate, which
catches the worst mistake, but the profile is worth checking while the old
credential is still signing:

```sh
openssl x509 -in signer.pem -noout -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
```

| Extension | Expected |
|---|---|
| Key Usage (critical) | `digitalSignature`, `nonRepudiation` |
| Basic Constraints (critical) | `cA=FALSE` |
| Extended Key Usage | `1.3.6.1.4.1.62558.2.1` plus `emailProtection` or `documentSigning`, and **not** `anyExtendedKeyUsage` |
| Certificate Policies | `1.3.6.1.4.1.62558.1.1` |
| `c2pa-al` | `1.3.6.1.4.1.62558.3.10` — Assurance Level 1 |
| `c2pa-cpl-record` | your CPL record UUID |
| Validity | at most 366 days |

Confirm the key and certificate are a pair before the maintenance window, not
during it:

```sh
diff <(openssl pkey -in signer.key -pubout) <(openssl x509 -in signer.pem -pubkey -noout)
```

### 2. Import, activate, verify

```sh
cat signer.pem intermediate.pem > chain.pem      # leaf first, trust anchor omitted

export CLAIM_SIGNER_KEYSTORE=/var/lib/claim-signer
export CLAIM_SIGNER_KEK_FILE=/run/secrets/claim-signer-kek

claim-signer import --id 2026-08-signer --key signer.key --chain chain.pem \
    --note "SSL.com free tier, AL1, order #…"
claim-signer versions                            # staged, not yet active
claim-signer activate --id 2026-08-signer        # then restart the service
```

Import and activate are separate commands so a new credential can be staged and
inspected while the old one is still signing. Then shred the plaintext key —
it is inside the keystore, sealed, and a second copy has no purpose.

```sh
curl -s https://sign.example.com/healthz | jq
curl -s https://sign.example.com/v1/identity | jq '{keyId, algorithm, assuranceLevel, cplRecordId, notAfter}'
```

`assuranceLevel` must be `1` and `cplRecordId` must be **your** UUID. If either
is null the certificate was not issued under the C2PA Certificate Policy, the
start-up log will have said so, and validators will not recognise manifests
signed with it as coming from a conforming Generator Product.

### 3. Smoke-test production

Same script, against the deployed URL, with a credential minted the way the
Edge gets one:

```sh
SECRET=$(curl -s -X POST https://app.example.com/api/edge-credential | jq -r .secret)
KEY_ID=$(curl -s -X POST https://app.example.com/api/edge-credential | jq -r .keyId)

./services/claim-signer/scripts/smoke-test.sh \
    --url https://sign.example.com --key-id "$KEY_ID" --secret "$SECRET"
```

Add the TLS checks from §5 above against the production hostname. If the
deployment sets `CLAIM_SIGNER_CLIENT_CA`, also confirm that a connection
*without* a client certificate is rejected — otherwise mutual TLS is configured
but not in force:

```sh
openssl s_client -connect sign.example.com:8443 -tls1_3            # expect a handshake failure
openssl s_client -connect sign.example.com:8443 -tls1_3 \
    -cert edge.pem -key edge.key                                   # expect success
```

### 4. Time-stamping

Point `CLAIM_SIGNER_TSA_URL` at the endpoint for your certificate's algorithm.
The claim signer is ES256, so the ECC endpoint is the match:

| Algorithm | Endpoint |
|---|---|
| ECC (ES256/ES384) | `https://api.c2patool.io/api/v1/timestamps/ecc` |
| RSA | `https://api.c2patool.io/api/v1/timestamps/rsa` |

Not optional in practice: an AL1 certificate lasts at most 366 days, and §15.8
judges an untimestamped manifest against the validity window *at the moment
someone looks at it*, so without a time-stamp every image the editor has signed
stops validating on the certificate's anniversary.

**Confirm which endpoint your account is entitled to before relying on one.** A
token fetched from the ECC endpoint above in August 2026 was granted under the
C2PA policy OID by `CN = SSL.com C2PA TSA SUB E1`, but its Authority Information
Access named `api.staging.c2pa.ssl.com` — a staging authority. That matters for
validation rather than for signing: the token carried only its leaf certificate,
its issuing intermediate (`SSL.com C2PA TSA ICA E1`) is not on the official C2PA
TSA Trust List, and the AIA URL that would supply it answered 404. A validator
that cannot complete the chain reports `timestamp.untrusted` — *informational*,
not a failure, so the manifest still validates but is judged at the current time
instead of the attested one, which is the whole benefit lost. Ask SSL.com for
the production endpoint and check the resulting token chains to
`SSL.com C2PA ECC Root CA 2025`, which is on the list.

Two other things to watch: the free tier's 10,000 stamps a year is one per
signature, so it is also a rate limit; and `CLAIM_SIGNER_TIMESTAMP_BUDGET`
(default 12288) is the space the Edge reserves in the manifest for the token —
if real tokens exceed it, exports fail after signing rather than before.

### 5. Trust lists for the editor

The C2PA lists, which the editor fetches at run time to answer the identity
question rather than reporting it unchecked:

| Repository variable | Value |
|---|---|
| `C2PA_TRUST_LIST_URL` | `https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem` |
| `C2PA_TSA_TRUST_LIST_URL` | `https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TSA-TRUST-LIST.pem` |

Both carry `SSL.com C2PA ECC Root CA 2025`, so an SSL.com-issued credential and
its time-stamps can both reach an anchor. The older
`verify.contentauthenticity.org/trust/` lists are the CAI *interim* lists and
say so in their own header: frozen, superseded by the official list above.

### 6. Point the editor at the Backend

| Repository variable | Value |
|---|---|
| `CLAIM_SIGNER_URL` | `https://sign.example.com`, or a same-origin prefix such as `/signer` |
| `EDGE_CREDENTIAL_ENDPOINT` | the path that mints a session credential, e.g. `/api/edge-credential` |

Set **both or neither**. The deploy workflow writes them into
`dist/claim-signer.json` with `printf`, so leaving `EDGE_CREDENTIAL_ENDPOINT`
unset produces `"credentialEndpoint":""` — a signer the editor can see and
cannot authenticate to, which surfaces as *this deployment has no way to
authenticate to the claim-signer* at export time rather than at deploy time.

The credential endpoint must be on the **page's own origin**: the Edge fetches it
with `credentials: 'same-origin'`, so a cross-origin endpoint gets no session
cookie and cannot know who is asking.

After deploying, check the published configuration is what you meant:

```sh
curl -s https://a10city.com/editor/claim-signer.json
```

### 7. End to end, from the deployed editor

Export a signed JPEG from the real site, then validate it against the real
lists — with `--validation-time` at *now*, which is what a stranger's validator
will use:

```sh
./target/release/c2pa-harness validate \
    --asset exported.jpg \
    --trust-list     C2PA-TRUST-LIST.pem \
    --tsa-trust-list C2PA-TSA-TRUST-LIST.pem \
    --validation-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --summary
```

Expect `signingCredential.trusted`, `timeStamp.validated`,
`claimSignature.insideValidity`, `claimSignature.validated` and
`assertion.dataHash.match`. Then cross-check with a second implementation —
[Verify](https://contentcredentials.org/verify) is the obvious one.

Two results that look like failures and are not:

- `signingCredential.untrusted` as **informational** means no trust list was
  configured, so nobody looked. That is a different statement from "the chain
  did not reach an anchor", and the interface says so in different words.
- `timestamp.untrusted` means the token could not be chained — see §4. The
  manifest is still valid; it is judged at the current time.

### 8. Rotation rehearsal

Rehearse it before the certificate expires, not during the incident:

```sh
claim-signer import   --id 2027-01-signer --key new.key --chain new.pem
claim-signer versions                      # both listed, old one still active
claim-signer activate --id 2027-01-signer
# restart, then re-run §2 and §3
```

Retired versions stay in the keystore — images signed under them are still in
the world. The Edge notices a rotation mid-export and retries rather than
shipping a signature that does not match the certificate already committed to in
the manifest, which is worth exercising at least once: export a file while the
restart is happening and confirm it comes out valid.

### 9. What to watch afterwards

| Signal | Where | Why |
|---|---|---|
| `notAfter` | `GET /healthz` | schedule the next enrolment 30 days ahead of it |
| `no time-stamp was obtained` | service log | the authority, the quota, or the egress path |
| `refused a signing request` rate | service log | credential minting or an abuse attempt |
| the 90-day CRITICAL/HIGH clock | CI | `conformance/scripts/vulnerability-scan.sh` fails the release when one goes over |

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| *This deployment has no signing service* | no `claim-signer.json`, or its `url` is empty |
| *The signing service could not be reached*, CORS error in the console | cross-origin without CORS headers; put the Edge and Backend behind one origin, or proxy |
| `/v1/identity` works, every `/v1/sign` is 401 | a proxy is not stripping its path prefix; the MAC covers the literal `/v1/sign` |
| *this deployment has no way to authenticate to the claim-signer* | `EDGE_CREDENTIAL_ENDPOINT` unset while `CLAIM_SIGNER_URL` is set |
| 401 with a correct secret | clock skew over 120 seconds between the Edge host and the service |
| `… is not set` at start-up | configuration is environment-only and fails closed; nothing is defaulted |
| *the TLS certificate and key do not go together* | mismatched pair in `CLAIM_SIGNER_TLS_CERT` / `_KEY` |
| the service starts but signs with the wrong certificate | `active` names a stale version; `claim-signer versions` |
| `timestampError: … UnknownIssuer` | the TSA leg trusts `webpki-roots`, not the OS store — an intercepting proxy breaks it |
| `timestamp.untrusted` in a validator | the token's chain does not reach an anchor on the TSA trust list |
| `signingCredential.untrusted` as informational | no trust list configured — the correct result, not a bug |
