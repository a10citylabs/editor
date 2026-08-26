# Test credentials

A test PKI, shaped exactly like the one a Certification Authority will issue,
so that every code path a real certificate exercises is exercised in CI first.

**Nothing here is trusted by anything outside this repository, and nothing here
is used by a deployment.** The keys are committed on purpose — they are test
fixtures, like a sample JPEG — and they are behind a Cargo feature (`test-pki`)
that no shipping build enables.

## What changed, and why the old README is gone

This directory used to be called `signing/` and held the key the browser signed
with. That key was public because it had to be: anything served to a browser is
downloadable by whoever receives it. The old README argued, correctly, that this
was an honest arrangement rather than a mistake.

It was also disqualifying. Objective **O.2** of the C2PA Generator Product
Security Requirements asks for a claim signing key that is encrypted at rest,
encrypted in memory except while signing, access-controlled by least privilege,
and rotatable. A key in a WebAssembly bundle is none of those, so Assurance
Level 1 — and therefore any certificate a validator would recognise — was out of
reach. See `conformance/README.md` for what replaced it.

So these files no longer sign anything a user will see. They exist to test.

## What is generated

```text
c2pa-test-root-ca.pem            self-signed root
c2pa-test-issuing-ca.pem         claim signing issuing CA, pathlen:0
c2pa-test-claim-signer.pem       the leaf, Assurance Level 1 profile
c2pa-test-claim-signer.key       its PKCS#8 key
c2pa-test-claim-signer-chain.pem leaf + issuing CA, the x5chain
c2pa-test-trust-list.pem         the root, as a trust list

tsa-test-root-ca.pem             a time-stamping authority root
tsa-test-signer.pem              its signer, timeStamping EKU, critical
tsa-test-signer.key
c2pa-test-tsa-trust-list.pem     the TSA root, as a TSA trust list
```

Regenerate with:

```sh
./conformance/test-credentials/generate.sh
```

Requires OpenSSL 3. It verifies both chains and prints the leaf's extensions
before finishing.

## The profile, and why it is followed exactly

`generate.sh` implements the *C2PA Claim Signing Leaf — Assurance Level 1*
profile from the C2PA Certificate Policy v0.2, including the parts it would have
been easier to skip:

| Property | Value | Why it is not simplified |
|---|---|---|
| Validity | **366 days** | The real ceiling. A twenty-year test certificate would hide the expiry handling and make the time-stamp path untestable — and expiry is exactly what time-stamping exists to survive |
| Extended Key Usage | `1.3.6.1.4.1.62558.2.1` + `emailProtection` | `c2pa-kp-claimSigning` is a C2PA-private OID that no generic tooling knows; the parser has to read it, so the fixture has to carry it |
| `c2pa-al` | `1.3.6.1.4.1.62558.3.10` | The Assurance Level is shown in the interface and in crJSON. Without it in the fixture, that display is untested |
| `c2pa-cpl-record` | the nil UUID | The right shape, and obviously not a real record. Override with `C2PA_CPL_RECORD_ID` once the product is listed |
| Key Usage | critical, `digitalSignature` + `nonRepudiation` | Path validation checks it |
| Basic Constraints | critical, `cA=FALSE` | §14.5 forbids a CA certificate signing a claim, and the validator enforces it |
| AIA | an OCSP URI | Parsed and reported; `signingCredential.ocsp.skipped` depends on knowing one exists |
| Certificate Policies | `1.3.6.1.4.1.62558.1.1` | Parsed |

The chain is three deep — root, issuing CA, leaf — rather than two, because a
real CA hierarchy has an intermediate and chain building has to walk one.
`x5chain` carries the leaf and the intermediate but never the root (§13.2.2).

### The 366-day expiry, and tests that do not rot

Certificates that last a year would normally make a test suite a time bomb. The
tests avoid it by deriving their validation time from the certificate rather
than hard-coding a date:

```rust
testpki::validation_time()   // notBefore + one day
testpki::after_expiry()      // notAfter + one day
```

So regenerating the PKI moves the tests with it, and the expiry paths stay
genuinely tested instead of being postponed.

## The stand-in time-stamping authority

`imagecore::c2pa::testpki::issue_timestamp` issues a real RFC 3161
`TimeStampToken` with the TSA key above: CMS `SignedData` wrapping a `TSTInfo`,
signed over DER-encoded signed attributes rather than over the payload directly.

Mocking it would have tested the mock. What the validator has to cope with is
the real structure — including the fact that the signature covers a *digest* of
the payload carried in an attribute, which is the classic place to get CMS
verification wrong. One of the tests moves a digit inside `genTime` and asserts
the token stops validating.

## Never used in production

Three things keep these files out of a deployment, in increasing order of how
much they would catch:

1. They are reachable only behind the `test-pki` Cargo feature, which is not in
   `imagecore`'s default features.
2. `conformance/scripts/check-no-key-material.sh` fails the build if the normal
   dependency graph links a private-key parser at all.
3. The same script searches the built `.wasm` for PEM private-key headers and
   for the literal bytes of the key above, in DER and in Base64.

All three run in CI and again before deployment.
