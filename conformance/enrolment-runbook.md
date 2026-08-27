# Getting a real claim signing certificate

The order of operations matters here and is easy to get wrong, so this is
written as a runbook rather than as prose. Nothing in it can be short-circuited:
a Certification Authority on the C2PA Trust List will only issue a claim signing
certificate to a product that is already on the Conforming Products List, and
that listing is what the rest of this directory exists to earn.

```text
  Expression of Interest ──▶ legal agreement ──▶ Intake Form ──▶ GPSA + evidence
                                                                        │
                                                                        ▼
  certificate ◀── CA enrolment ◀── CPL record id ◀── assessment and approval
       │
       ▼
  claim-signer import / activate
```

---

## 1. Apply to the Conformance Program

The [Expression of Interest form][eoi] asks for the applicant's legal entity and
which roles are being applied for. This product is a **Generator Product**, and
it also validates, so the Generator Product application covers both — the
Program treats validation functionality inside a Generator Product under the
same agreement, and asks for crJSON evidence of it.

[eoi]: https://github.com/c2pa-org/conformance-public

Then a legal agreement, then the Program Intake Form. The Intake Form is where
the answers have to match this repository:

| Field | Answer | Where it comes from |
|---|---|---|
| Specification version | **2.2** | `imagecore::c2pa::SPEC_VERSION` |
| Implementation class | **Distributed** | GPSA §1.7 |
| Target Max Assurance Level | **1** | GPSA §1.8 |
| Generate media types | `image/jpeg` | GPSA §1.9 |
| Validate media types | `image/jpeg` | GPSA §1.9 |
| Ingests manifests as ingredients | Yes | Sample `04-two-generations` |

The specification version is a contract, not a note: it has to equal the
`specVersion` written into every manifest, and changing one without the other
puts the product out of conformance.

## 2. Submit the architecture document and the evidence

```sh
./conformance/scripts/generate-evidence.sh   # sample assets + crJSON
./conformance/scripts/sbom.sh                # CycloneDX SBOMs
./conformance/scripts/vulnerability-scan.sh  # the 90-day gate report
```

Submit:

- `conformance/generator-product-security-architecture.md`, with §1.1 and the
  `O`/`C` fields of §1.4 filled in with the real legal entity
- the five sample assets and their crJSON from `conformance/evidence/`
- the SBOMs and the gate report

The Program also supplies its own asset library. Run the harness over it and
submit those results too — the only thing that changes is the path:

```sh
./target/release/c2pa-harness batch \
    --asset-dir  <the Program's assets> \
    --output-dir conformance/evidence/crjson-program \
    --trust-list <the Program's test trust list> \
    --tsa-trust-list <the Program's test TSA trust list> \
    --validation-time <the time the Program specifies>
```

## 3. Take the CPL record id

Approval produces a Conforming Products List record with a UUID. Two places
need it:

1. **The certificate.** The CA puts it in the `c2pa-cpl-record` extension
   (OID `1.3.6.1.4.1.62558.4`) of the leaf. Nothing in this repository writes
   it; the code *reads* it and shows it.
2. **The test PKI**, so local runs look like production:

   ```sh
   C2PA_CPL_RECORD_ID=<the UUID> ./conformance/test-credentials/generate.sh
   ```

## 4. Enrol with a conformant CA

Any Certification Authority on the C2PA Trust List. [SSL.com][ssl] offers a free
tier for conformant Generator Products which, at the time of writing, provides
one Assurance Level 1 claim signing certificate valid for a year and 10,000
trusted time-stamps annually, issued through their portal, and which requires a
valid C2PA conformance record id — that is the UUID from step 3.

[ssl]: https://www.ssl.com/products/content-authenticity/content-credentials/c2pa/

Generate the key **on the Backend host**, so it never travels:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out signer.ec.key
openssl pkcs8 -topk8 -nocrypt -in signer.ec.key -out signer.key
openssl req -new -key signer.ec.key -out signer.csr -subj \
  "/C=<CC>/O=<legal name>/CN=A10city Image Editor"
```

The subject must match the Conforming Products List entry exactly — the
Certificate Policy requires `C`, `O` and `CN`, and the CA checks them against
the record.

Submit `signer.csr` through the portal. What comes back should carry:

| Extension | Expected |
|---|---|
| Key Usage (critical) | `digitalSignature`, `nonRepudiation` |
| Basic Constraints (critical) | `cA=FALSE` |
| Extended Key Usage | `1.3.6.1.4.1.62558.2.1` plus `emailProtection` or `documentSigning`, and **not** `anyExtendedKeyUsage` |
| Certificate Policies | `1.3.6.1.4.1.62558.1.1` |
| `c2pa-al` | `1.3.6.1.4.1.62558.3.10` (Assurance Level 1) |
| `c2pa-cpl-record` | the UUID from step 3 |
| Authority Information Access | an OCSP URI |
| Validity | at most 366 days |

Check before importing, rather than discovering a mismatch in a validator later:

```sh
openssl x509 -in signer.pem -noout -text | sed -n '/X509v3 extensions/,/Signature Algorithm/p'
```

## 5. Import it

```sh
cat signer.pem intermediate.pem > chain.pem   # leaf first, root omitted

export CLAIM_SIGNER_KEYSTORE=/var/lib/claim-signer
export CLAIM_SIGNER_KEK_FILE=/run/secrets/claim-signer-kek

claim-signer import --id 2026-08-signer --key signer.key --chain chain.pem \
    --note "SSL.com free tier, AL1, order #…"
claim-signer activate --id 2026-08-signer
```

`chain.pem` carries the leaf and every intermediate but **never the trust
anchor** (C2PA 2.2 §13.2.2). Import refuses a CA certificate as the leaf, and
the service refuses to start if the key does not match the certificate beside
it, so both mistakes fail loudly at the point they are made.

Then shred the plaintext key:

```sh
shred -u signer.key signer.ec.key signer.csr
```

It is inside the keystore, sealed under the key-encryption key, and there is no
reason for a second copy to exist.

## 6. Configure time-stamping

```sh
export CLAIM_SIGNER_TSA_URL=<the CA's RFC 3161 endpoint>
```

Not optional in practice. An Assurance Level 1 certificate lasts at most 366
days, and §15.8 of the specification judges an untimestamped manifest against
the validity window *at the moment someone looks at it* — so without a
time-stamp every image the editor has ever signed stops validating on the
certificate's anniversary. With one, a validator judges the certificate at the
attested time instead, and the credential stays good.

The Backend fetches a stamp over each signature and returns it with the
signature. When the authority is unreachable the file is still written, the
response says why there is no stamp, and the interface passes that on — refusing
to save someone's photograph because a third party was down would be the wrong
trade.

## 7. Point the editor at the Backend

Two repository variables in the deploy workflow:

| Variable | Value |
|---|---|
| `CLAIM_SIGNER_URL` | `https://sign.example.com` |
| `EDGE_CREDENTIAL_ENDPOINT` | the path that mints a session credential |

which the workflow writes into `dist/claim-signer.json`. Absent, the editor runs
without signing and says so; there is no half-configured state.

Publish the trust lists too, so the validator can answer the identity question
rather than reporting it unchecked:

| Variable | Value |
|---|---|
| `C2PA_TRUST_LIST_URL` | the C2PA Trust List PEM bundle |
| `C2PA_TSA_TRUST_LIST_URL` | the C2PA TSA Trust List PEM bundle |

## 8. Verify end to end

```sh
curl -s https://sign.example.com/healthz | jq
curl -s https://sign.example.com/v1/identity | jq '{keyId, algorithm, assuranceLevel, cplRecordId, notAfter}'
```

Then export a signed JPEG from the deployed editor and validate it against the
real trust lists:

```sh
./target/release/c2pa-harness validate \
    --asset exported.jpg \
    --trust-list c2pa-trust-list.pem \
    --tsa-trust-list c2pa-tsa-trust-list.pem \
    --validation-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --summary
```

Expect `signingCredential.trusted`, `timeStamp.validated`,
`claimSignature.insideValidity`, `claimSignature.validated` and
`assertion.dataHash.match`. Cross-check with a second implementation —
[Verify][verify] is the obvious one — because agreeing with yourself proves
nothing.

[verify]: https://contentcredentials.org/verify

The full procedure — including the TLS and authentication checks this section
skips, the two results that look like failures and are not, and where to get the
trust list PEMs — is [`services/claim-signer/TESTING.md`](../services/claim-signer/TESTING.md).

---

## Keeping it

**Rotate before expiry, not after.** Schedule the next enrolment 30 days before
`notAfter`. `GET /healthz` reports it, so a monitor can alert on it. Staging is
separate from activating precisely so the new credential can be imported and
inspected while the old one is still signing.

**Keep retired versions.** Images signed under them are still in the world.

**Watch the 90-day clock.** Every CI run prints the countdown on each open
CRITICAL or HIGH finding, and the gate fails the release when one goes over.
That is not a formality: releasing past it is a conformance failure under O.3
and O.4.

**Tell the Program when things change.** Re-submitting evidence is required when
the specification version changes, when the supported media types change, or
when the architecture changes in a way that touches the GPSA.
