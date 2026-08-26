# C2PA Generator Product Security Architecture

**A10city Image Editor** · Conformance Program v0.2 · Target Max Assurance Level 1

> This follows the *C2PA Generator Product Security Architecture Document
> Template* v0.2 section for section, so an assessor can read it beside the
> template. Where the template asks for something an applicant supplies at
> submission time rather than something that lives in a repository — a legal
> entity, a signed attestation, a cloud account's IAM export — the section says
> so plainly and states what has to be filled in. Nothing here is asserted that
> the code does not actually do; every claim names the file that implements it.

---

## 1. Generator Product Information

### 1.1 Applicant organization details

**To be completed at submission.** The Program Intake Form requires the full
legal name, registered address and contact details of the applicant
organisation. The distinguished name in §1.4 must match the legal name given
here, and the Conforming Products List record is built from it.

### 1.2 C2PA Conformance Program Version

**0.2**

### 1.3 C2PA Content Credentials Specification Version

**2.2**

Declared in one place in the source, `imagecore::c2pa::SPEC_VERSION`, and
written into every manifest as the `specVersion` field of
`claim_generator_info`. The *Additional Conformance Requirements* make that a
contract: the value has to match the version on the Conforming Products List
record, so changing it here without changing the listing puts the product out of
conformance. A test asserts the two are the same string
(`crates/imagecore/src/c2pa/mod.rs`, `the_generator_declares_the_specification_version`).

### 1.4 Distinguished name

| Field | Value |
|---|---|
| Common Name (CN) | `A10city Image Editor` |
| Organization (O) | *the applicant's registered legal name* |
| Organizational Unit (OU) | *omitted* |
| Country (C) | *ISO 3166-1 alpha-2 of the applicant's base of operations* |

The test PKI under `conformance/test-credentials/` issues a leaf with exactly
this shape, so the parsing, display and validation paths are exercised against a
correctly formed subject long before a real certificate arrives.

### 1.5 Generator Product Description

A browser-based raster image editor. A person opens a photograph, crops,
straightens, rotates, resizes and adjusts it, and exports the result. Decoding,
every pixel operation and encoding happen inside the browser tab in a
WebAssembly module compiled from Rust; the image is never uploaded.

When the export format is JPEG and a signing service is configured, the export
carries C2PA Content Credentials describing what was done to it: one action per
operation the user actually performed, each with the parameters that describe it
(`c2pa.cropped` with the rectangle, `c2pa.resized` with the dimensions, and so
on), plus a `c2pa.opened` action and a `parentOf` ingredient naming the file
that was opened. Where that file carried its own credentials, its manifests are
copied forward so the provenance chain stays walkable from the finished file
alone.

The product also validates: any JPEG opened in the editor is checked, and the
result is shown before the user does anything to it.

### 1.6 Generator Product Target of Evaluation (GP TOE) Description

```text
┌─ Edge subsystem ─────────────────────────┐   ┌─ Backend subsystem ──────────────┐
│  the user's browser tab                  │   │  services/claim-signer            │
│                                          │   │                                   │
│  apps/editor          UI, worker         │   │  keystore.rs   sealed signing key │
│  crates/imagecore     decode, edit,      │   │  auth.rs       caller auth (O.2)  │
│    (WebAssembly)      encode, assertions,│   │  tsa.rs        RFC 3161 client    │
│                       claim, validation  │   │                                   │
│                                          │   │  holds: the ONLY claim signing    │
│  holds: no key material of any kind      │   │         key in the system         │
└──────────────┬───────────────────────────┘   └────────────┬──────────────────────┘
               │                                            │
               │   Sig_structure (claim + x5chain, ~1 KB)   │
               ├────────────── TLS 1.3 ─────────────────────▶
               │        no pixels ever cross this line      │
               ◀────────── signature + TimeStampToken ──────┤
                                                            │
                                                            │ RFC 3161, TLS
                                                            ▼
                                              ┌─ outside the TOE ──────────┐
                                              │  Time-Stamping Authority   │
                                              │  (receives a 32-byte hash) │
                                              └────────────────────────────┘
```

Everything inside both boxes is in the Target of Evaluation, because both are
"necessary for the proper operation of the Generator Product" in the Program's
terms: the Edge produces the assertions referenced in `created_assertions`, and
the Backend performs the signing and holds the key. The user's browser and
operating system are the Edge's hosting platform; the Backend's container host
and its cloud account are the Backend's.

Explicitly **outside** the TOE: the Time-Stamping Authority (a third-party
service, on the C2PA TSA Trust List, which receives a digest and nothing else),
and the Certification Authority.

**What changed, and why it is the whole point of this submission.** An earlier
version of this product compiled a signing key into the WebAssembly module. That
is disqualifying under O.2 at any Assurance Level, and no amount of obfuscation
changes it: whatever a browser is served, its user has. The product was
re-architected as a Distributed implementation specifically so the key could
live somewhere that satisfies O.2. `conformance/scripts/check-no-key-material.sh`
enforces the outcome mechanically in CI — it fails the build if the shipped
`.wasm` contains a PEM private-key header, the bytes of the test key, or a
dependency edge on any private-key parsing feature.

### 1.7 Implementation Class

**Distributed.** Assets, assertions and claims are generated on the Edge; claim
signatures are generated on the Backend.

### 1.8 Target Max Assurance Level

**1.**

Level 2 is out of reach and the reason is architectural rather than a matter of
effort: it requires the Generator Product to produce verifiable artefacts backed
by a hardware Root of Trust from the platform the Claim Generator runs on. A web
page has no such facility. Reaching Level 2 would mean shipping a native
application, which is a different product.

### 1.9 Target Generator Product capabilities

**Claim generation:**

- `image/jpeg`

**Claim validation (ingestion of manifests as ingredients):**

- `image/jpeg`

One media type, chosen rather than defaulted. The hard binding this generator
writes is `c2pa.hash.data`, which commits to a byte range of the finished file,
so the manifest must be embeddable at a known offset and the exclusion rules
have to be written per format (§18.5.3 for JPEG, §18.5.4 for PNG, and so on).
JPEG's `APP11` segments are the case the specification treats in most detail.
Every other format the editor supports keeps working as an ordinary editor and
simply does not get a credential; the interface says which and why rather than
greying out a control with no explanation.

The product ingests manifests: opening a JPEG that carries credentials validates
them, shows the result, and — if the user exports — copies the manifests forward
and records a `parentOf` ingredient with the validation results of the parent.
Sample assets demonstrating ingestion are produced by
`conformance/scripts/generate-evidence.sh`.

---

## 2. Security Architecture Details by Objective

### 2.1 [O.1] Automated Certificate Enrollment Proof of Eligibility

**Applicability: not applicable.** The requirement opens "The following
requirements are only applicable if conforming GP instances rely on automated
certificate enrollment for initial certificate issuance or rotation."

#### 2.1.1 Assurance Level 1 & 2 Base Evidence

1. **Certificate enrollment process.** Enrollment is manual and performed by a
   named operator through the Certification Authority's portal, not by an
   instance of the Generator Product. SSL.com's free tier for conformant
   Generator Products is portal-issuance only, which fits this exactly. The
   operator generates a key pair on the Backend host, produces a CSR, submits it
   through the portal against the product's Conforming Products List record id,
   and imports the issued certificate with `claim-signer import`. The procedure,
   step by step, is `conformance/enrolment-runbook.md`.

   No Generator Product instance ever authenticates to a CA, so there is no
   enrollment credential in any binary, and requirement 2 for the Edge
   Implementation Class ("the GP TOE binary/binaries SHALL NOT include
   authentication secrets") is satisfied vacuously as well as in fact.

2. **Authentication method & API details.** Not applicable while enrollment is
   manual. If this product later moves to an API-issued certificate — which the
   premium tiers of conformant CAs offer — this section will be updated within
   the 90 days the requirement allows, and the enrollment credential will be
   held in the Backend's key management service alongside the key-encryption
   key, never in a shipped artefact.

3. **Management of authentication secrets.** None exist. See above.

#### 2.1.2 Assurance Level 2 Additional Evidence

Not applicable: Level 1 is the target, and enrollment is not automated.

---

### 2.2 [O.2] Confidentiality of the Claim Signing Key

This is the objective the architecture was rebuilt around. Implementation:
`services/claim-signer/src/keystore.rs` and `services/claim-signer/src/auth.rs`.

#### 2.2.1 Assurance Level 1 & 2 Base Evidence

1. **Key generation & storage.** The claim signing key is an ECDSA P-256 key
   (NIST FIPS 186-4; `secp256r1`), generated on the Backend host with OpenSSL 3
   and never transmitted. P-384 is also supported by the keystore for a
   deployment whose CA issues on that curve.

   At rest, the key is stored as `nonce ‖ AES-256-GCM(PKCS#8 DER)` in
   `<keystore>/<version>/key.enc`, mode `0600`. The additional authenticated
   data binds the ciphertext to its version id, so a `key.enc` cannot be lifted
   from a retired version into the active one — a test asserts that the move is
   detected rather than silently signing with the wrong key
   (`a_sealed_key_moved_between_versions_does_not_decrypt`).

   The key-encryption key is 32 bytes, supplied to the process from outside the
   filesystem holding the ciphertext. `CLAIM_SIGNER_KEK_FILE` (a mounted secret,
   preferred) takes precedence over `CLAIM_SIGNER_KEK` (an environment
   variable), because an environment variable is readable by anything that can
   read `/proc`. In the reference deployment the file is projected from the
   cloud provider's secret manager. The service logs which source it used at
   start-up, so a production deployment cannot quietly be running on a
   development configuration.

2. **Access controls & encryption.** The plaintext key is never held by any
   long-lived object. `Keystore` owns the ciphertext only; there is no accessor
   that returns the key, and the sole entry point is `Keystore::sign`, which
   decrypts, signs and drops. That is deliberate design rather than discipline —
   a key that cannot be obtained cannot be leaked by the next person to add a
   feature.

   On the host, the sealed key is `0600` and owned by the service's dedicated
   unprivileged account. The account has no shell and no other role. The
   key-encryption key is readable only by that account.

3. **Ephemeral plaintext key handling.** The decrypted PKCS#8 DER lives in a
   `zeroize::Zeroizing<Vec<u8>>`, which overwrites its buffer on drop; the
   `p256`/`p384` `SigningKey` types zero their own scalars on drop. The window
   is one function call with no I/O and no `await` inside it. The release
   profile sets `panic = "abort"`, so a panic during signing terminates the
   process rather than unwinding through a handler that could observe the key —
   fail-closed is the right posture for a component whose only job is to hold
   one secret.

   The non-GP code that touches the plaintext is `aes-gcm`, `p256`, `p384` and
   `zeroize` from the RustCrypto project. Their vulnerability monitoring is the
   same pipeline as everything else: SBOM plus `cargo-audit` on every pull
   request and before every release, with the 90-day gate described in §2.3.1.

4. **Key rotation process.** Two commands, deliberately separate so a new
   credential can be staged and inspected before anything signs with it:

   ```text
   claim-signer import   --id 2027-01-signer --key new.key --chain new.pem
   claim-signer activate --id 2027-01-signer
   ```

   Retired versions are kept, not deleted: images signed under them are still in
   the world, and the certificate has to remain available to explain them. The
   active version's id is published in `GET /v1/identity` and returned with every
   signature; the Edge refuses to complete an export whose signature came back
   under a different key id than the certificate it already committed to in the
   manifest.

   Triggers: certificate expiry (Assurance Level 1 caps a claim signing leaf at
   366 days, so rotation is at minimum annual and is scheduled 30 days before
   `notAfter`), suspected compromise, and any change of Certification Authority.

5. **Subsystem mutual authentication & role validation.**

   *Backend authenticates Edge.* Every `/v1/sign` request carries an
   `Authorization: C2PA-HMAC-SHA256` header whose MAC covers the method, the
   path, a timestamp, a nonce and a digest of the body — symmetric key MAC, one
   of the methods the requirement names. MACing the request rather than issuing
   a bearer token is what stops a captured header being pointed at a different
   claim. The comparison is constant-time; the timestamp must be within 120
   seconds; nonces are remembered for that window so a request cannot be
   replayed; and a failed authentication does not consume its nonce, so an
   attacker cannot burn one they observed. Unknown-key and bad-MAC are reported
   identically to the caller so the endpoint is not an oracle for enumerating
   key ids, while the log distinguishes them.

   The Edge secret is a session credential minted by the application server for
   a signed-in session, short-lived, and rate-limited per session. Its role is
   exactly the one the requirement scopes it to — "only for the purposes of
   limiting access to the Backend subsystem" — and not identity: a browser
   cannot keep a secret, and the C2PA trust model rests on the Backend's key,
   not on this one.

   *Edge authenticates Backend.* TLS 1.3, against a URL fixed in the Edge's
   configuration. Where a deployment can also issue client certificates,
   `CLAIM_SIGNER_CLIENT_CA` turns on mutual TLS and the HMAC layer sits inside
   it.

   *Role validation.* Two roles, and neither can perform the other's operations.
   The Edge role may call `GET /v1/identity` and `POST /v1/sign` and nothing
   else; the routing table has no other authenticated route. Key import and
   activation are not HTTP operations at all — they are subcommands run by an
   operator on the host, which removes the whole class of "an Edge credential
   was used to rotate the key" from the design.

#### 2.2.2 / 2.2.3 Assurance Level 2 Additional Evidence

Not applicable at the target level. For the record, the keystore is written
against a `sign(message) -> signature` boundary, so moving to a KMS or an HSM
is a change to one implementation and not to the service around it.

---

### 2.3 [O.3] Protection of the Claim Generator

#### 2.3.1 Assurance Level 1 & 2 Base Evidence

1. **SCA / SBOM scanning tools.**

   | Tool | Scope | Output |
   |---|---|---|
   | `cargo-cyclonedx` | every Rust crate in the TOE | CycloneDX 1.5 JSON |
   | `npm sbom` | the browser application | CycloneDX JSON |
   | `cargo-audit` | Rust dependencies, against the RustSec advisory database (NVD-mapped) | JSON |
   | `npm audit` | JavaScript dependencies, against the GitHub Advisory Database (NVD-mapped) | JSON |

   Driven by `conformance/scripts/sbom.sh` and
   `conformance/scripts/vulnerability-scan.sh`. Both run in CI on every pull
   request (`.github/workflows/ci.yml`, job `supply-chain`) and the second runs
   again before every release (`.github/workflows/deploy.yml`). SBOMs and scan
   output are uploaded as build artefacts and land in
   `conformance/evidence/`.

2. **90-day remediation policy.** The gate is
   `conformance/scripts/gate.py`, and it is a gate rather than a report: a
   non-zero exit fails the job, and the release workflow runs it *before* the
   build step so a blocked release cannot be published.

   The rule needs a memory, because a scanner only knows about today, and the
   question is not "are there findings" but "has any finding been open too
   long". `conformance/vulnerability-ledger.json` is that memory. It is
   committed, so the clock survives a fresh runner and an assessor can see the
   history:

   ```text
   first seen + 90 days < today   →  the build fails
   otherwise                      →  the build passes, printing the countdown
   ```

   Three further behaviours are deliberate. A CRITICAL or HIGH finding that is
   *not* in the ledger also fails the build, so the clock cannot be avoided by
   never recording a finding. A finding may be marked `accepted` with a written
   reason, which is visible in the diff that adds it. And a finding the scanners
   stop reporting is marked `resolved` with a date rather than deleted, so how
   long each fix took is on the record.

#### 2.3.2 Assurance Level 2 Additional Evidence

Not applicable at the target level. Noted for context: the Claim Generator is
written in safe Rust with no `unsafe` blocks in the C2PA modules, `cargo clippy`
runs with `-D warnings` in CI, and the browser is a sandboxed execution
environment with ASLR and W^X — but none of that is offered as Level 2 evidence,
because Level 2 turns on hardware-backed attestation the platform cannot give.

---

### 2.4 [O.4] Protection of Assets & Assertions at Generation

#### 2.4.1 Assurance Level 1 & 2 Base Evidence

1. **SCA / SBOM scanning tools.** The same pipeline as §2.3.1, and deliberately
   the same scope: O.4 is the wider objective, covering "all software in GP TOE
   that processes/modifies the Digital Content and/or assertions", so the SBOM
   covers the image pipeline (`image`, `fast_image_resize`, `imageproc`), the
   claim generator, the browser application, and the claim-signer. There is no
   component of the TOE outside the scan.

2. **90-day remediation policy.** As §2.3.1. The gate does not distinguish which
   crate a finding is in, so a vulnerability in the resampling library blocks a
   release exactly as one in the signing path does.

#### 2.4.2 Assurance Level 2 Additional Evidence

Not applicable at the target level.

---

### 2.5 [O.5] Protection of Traffic Between Subsystems

#### 2.5.1 Assurance Level 1 & 2 Base Evidence (Distributed class)

1. **TLS 1.3 & cryptographic protocols.** The claim-signer's listener is
   configured with TLS 1.3 as the *only* permitted version, not as a minimum:

   ```rust
   rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
   ```

   `services/claim-signer/src/main.rs`, `tls_config`. A downgrade is impossible
   rather than merely discouraged. The stack is `rustls` 0.23 with the `ring`
   provider, whose TLS 1.3 suites are `TLS13_AES_256_GCM_SHA384`,
   `TLS13_AES_128_GCM_SHA256` and `TLS13_CHACHA20_POLY1305_SHA256`, with key
   exchange over X25519 and the NIST P-curves. Where the deployment sets
   `CLAIM_SIGNER_CLIENT_CA`, the same listener requires a client certificate
   validated by `WebPkiClientVerifier`.

   There is one non-conformant escape hatch and it announces itself:
   `CLAIM_SIGNER_ALLOW_PLAINTEXT` serves HTTP for local development and logs a
   warning naming this objective every time it starts.

   The Backend's outbound leg to the Time-Stamping Authority is also TLS, via
   `ureq` built against `rustls`; a native-TLS build was avoided so the
   negotiated protocol is not left to whatever the host OS happens to ship.

#### 2.5.2 Assurance Level 2 Additional Evidence

Not applicable at the target level.

---

### 2.6 [O.6] Protection of the Hosting Environment

**Applicability: Distributed class, so this applies to the Backend's hosting
environment only.** The Edge's hosting environment is the user's browser, which
is not the applicant's to configure.

The controls below are properties of a *deployment*, not of source code, so this
section describes what the reference deployment does and what an operator must
be able to evidence. `services/claim-signer/README.md` is the operational
counterpart.

#### 2.6.1 Assurance Level 1 & 2 Base Evidence

1. **IAM & Role-Based Access Control.** The claim-signer runs as a container in
   a single-purpose cloud project whose only workload is claim signing. Access
   is governed by the provider's IAM with RBAC. Three roles exist:

   | Role | May | Held by |
   |---|---|---|
   | `signer-runtime` | read the key-encryption key from the secret manager; write logs | the service's workload identity, nothing human |
   | `signer-operator` | run `import` / `activate`; read logs | two named individuals |
   | `signer-auditor` | read logs and configuration; no secret access | the security reviewer |

   No principal holds both `signer-operator` and the ability to alter the audit
   log destination.

2. **Principal access policies.** The runtime identity is a workload identity
   with no interactive login and no key of its own. Human access to the host is
   through the provider's session-recorded break-glass mechanism, requires
   multi-factor authentication, and is alerted on. Service accounts hold no
   long-lived credentials.

3. **Cloud resource IAM policies.** The secret holding the key-encryption key
   grants `get` to `signer-runtime` and to no other principal. The container
   registry grants pull to the runtime and push only to the release pipeline's
   identity. The keystore volume is mounted read-only by the runtime and
   writable only during an operator session. No storage bucket in the project is
   public.

4. **Vulnerability scanning & OWASP Top 10 coverage.** Dependency scanning is
   the pipeline in §2.3.1. The API surface is three endpoints, and the OWASP Top
   10 is covered as follows, since a list this short can be answered concretely
   rather than by assertion:

   | OWASP category | How it is addressed |
   |---|---|
   | A01 Broken access control | Two roles, enforced at the routing table; no authenticated route but `/v1/sign`; key import is not an HTTP operation at all |
   | A02 Cryptographic failures | TLS 1.3 only; AES-256-GCM at rest; constant-time MAC comparison; no home-grown primitives |
   | A03 Injection | No database, no shell, no templating. The only parsed inputs are Base64 and DER, into memory-safe Rust with explicit length checks |
   | A04 Insecure design | The signing key is unreachable by construction (§2.2.1); the request MAC covers the body so a captured credential cannot be re-aimed |
   | A05 Security misconfiguration | Configuration is environment-only and fails closed: a missing key-encryption key, client list or TLS certificate refuses to start. The plaintext-HTTP escape hatch logs a warning naming O.5 |
   | A06 Vulnerable components | §2.3.1 |
   | A07 Authentication failures | MAC with replay protection and a 120-second window; identical responses for unknown key and bad MAC; no passwords and no sessions |
   | A08 Data integrity failures | The signed artefact is verified against the certificate at start-up; a time-stamp is checked against the signature it should cover before being returned |
   | A09 Logging failures | Structured JSON logs of every signature (client, key id, digest of the signature, whether it was time-stamped) and every refusal with its reason. The claim itself is never logged |
   | A10 Server-side request forgery | One outbound destination, the TSA URL, fixed in configuration and never taken from a request |

   A request body limit of 256 KiB and a 30-second timeout bound the resources
   any one caller can consume.

5. **Timely remediation policy.** High severity within 30 days, Moderate within
   90, Low within 180 — the timeline the template names — measured from
   detection and tracked in the same ledger as §2.3.1. Operating system and base
   image patches are applied by rebuilding and redeploying the container; the
   base image is rebuilt weekly and on any advisory affecting it.

#### 2.6.2 Assurance Level 2 Additional Evidence

Not applicable at the target level.

---

## 3. What is not yet in place

Stated plainly rather than left for an assessor to discover, because the
Conformance Program's value depends on applicants being straight about this.

| Item | State |
|---|---|
| Legal entity details (§1.1, §1.4 `O` and `C`) | To be filled in at submission |
| A real claim signing certificate | Not yet issued. The product is not on the Conforming Products List, so no conformant CA can issue one — the ordering of the programme, not an omission. See `conformance/enrolment-runbook.md` |
| Production Backend deployment | The service is complete and tested; §2.6 describes the deployment an operator must stand up and evidence |
| C2PA Trust List and TSA Trust List in the shipped app | Fetched at run time from `trust-lists/` when the deployment publishes them; absent on the static build, where the validator reports signer identity as unchecked rather than guessing |
| crJSON against the Program's own asset library | The harness is complete and produces crJSON from this repository's assets; point `--asset-dir` at the Program's library when it is supplied |
