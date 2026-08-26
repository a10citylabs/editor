# C2PA conformance

Everything in this directory exists to answer one question: **what would it take
for the Content Credentials this editor writes to be worth believing?**

The answer is not more code in the browser. It is a certificate issued by a
Certification Authority on the C2PA Trust List, and that is only issued to a
product on the [Conforming Products List][cpl] — which in turn requires meeting
the [C2PA Generator Product Security Requirements][gpsr] at Assurance Level 1 or
higher. So the work here is half implementation and half evidence.

[cpl]: https://github.com/c2pa-org/conformance-public
[gpsr]: https://github.com/c2pa-org/conformance-public/tree/main/docs/v0.2

## The one change that mattered

An earlier version of this product compiled its signing key into the WebAssembly
module. It was honest about the consequence — the interface said the identity
was unverifiable — but honesty is not conformance. Objective **O.2** of the
security requirements asks for a claim signing key that is:

- stored encrypted at rest,
- kept encrypted in volatile memory except while signing,
- access-controlled by least privilege, and
- rotatable.

A key served to every visitor fails all four, and the failure is not a matter of
degree. That put Assurance Level 1 — and therefore the Conforming Products List,
and therefore any certificate anyone would trust — permanently out of reach.

So the product was re-architected as a **Distributed** implementation:

```text
 Edge (the browser tab)                     Backend (services/claim-signer)
 ──────────────────────                     ───────────────────────────────
 decode, edit, encode                       the only claim signing key
 build assertions and the claim             AES-256-GCM at rest
 compute the Sig_structure   ── TLS 1.3 ──▶ authenticate the caller
 (~1 KB: no pixels)                         decrypt for one operation, sign
                                            fetch an RFC 3161 time-stamp
 assemble COSE_Sign1, embed  ◀────────────  signature + TimeStampToken
```

The editor's promise is unchanged: **the image still never leaves the tab.**
What crosses the network is a claim and a certificate chain. The signature moved
because it had to; the picture did not.

`scripts/check-no-key-material.sh` enforces the outcome mechanically on every
build — it fails if the shipped `.wasm` contains a PEM private-key header, the
bytes of the test key, or so much as a dependency edge on a private-key parser.

## What is here

| File | What it is |
|---|---|
| `generator-product-security-architecture.md` | The GPSA document the Program requires, written against its template |
| `requirements-matrix.md` | Every Level 1 requirement, and the file or test that meets it |
| `enrolment-runbook.md` | How to get a real certificate, once the product is listed |
| `test-credentials/` | A test PKI shaped exactly like the real thing |
| `scripts/` | SBOM, the 90-day vulnerability gate, the key-material check, evidence generation |
| `vulnerability-ledger.json` | When each CRITICAL/HIGH finding was first seen — the memory the 90-day rule needs |
| `evidence/` | Generated; not committed. See below |

## Producing the evidence

```sh
# Sample assets and their crJSON, which is what the Program asks applicants for.
./conformance/scripts/generate-evidence.sh

# Software Bill of Materials for every component of the Target of Evaluation.
./conformance/scripts/sbom.sh

# The 90-day CRITICAL/HIGH gate. Exits non-zero when something is overdue.
./conformance/scripts/vulnerability-scan.sh

# Prove the browser bundle holds no key material.
./conformance/scripts/check-no-key-material.sh
```

All four run in CI (`.github/workflows/ci.yml`), and the vulnerability gate runs
again before every deployment, because a gate that only advises is not a gate.

Output lands in `evidence/` and is deliberately not committed: it is derived,
it churns, and CI uploads it as a build artefact where an assessor can fetch a
specific run. One command reproduces it.

### What the samples cover

`generate-evidence.sh` produces five assets, chosen so each shows a different
thing rather than five variations of one:

| Asset | Shows |
|---|---|
| `01-edited-timestamped` | The ordinary case: several edits, a thumbnail, a trusted time-stamp |
| `02-no-timestamp` | What the validator reports when the TSA was unreachable |
| `03-opened-unchanged` | Opening and saving without editing — the actions say so honestly |
| `04-two-generations` | Manifest ingestion: a `parentOf` ingredient and the parent's manifest carried forward |
| `05-tampered-pixels` | A file that must fail, and which check catches it |

## Where this stands

**Implemented and tested.** The architecture, the claim generator, the
validator, the trust-list path validation, RFC 3161 time-stamping, the crJSON
harness, and the supply-chain gate. `cargo test --workspace` covers all of it.

**Waiting on the Program, not on code.** A real claim signing certificate cannot
exist until the product is on the Conforming Products List, and the listing
requires submitting the GPSA and the evidence above. That ordering is the
Program's, and it is the right way round.

**Deployment work.** Objective O.6 is about a hosting environment, and a
repository cannot contain one. `generator-product-security-architecture.md` §2.6
describes the IAM roles, access policies and monitoring an operator has to stand
up and evidence; `services/claim-signer/README.md` is the operational side.

Section 3 of the GPSA lists what is outstanding, in one table, rather than
leaving an assessor to find it.

## Reading order

1. `generator-product-security-architecture.md` §1 — what the product is and
   where its boundary lies
2. `crates/imagecore/src/c2pa/identity.rs` — why the key left the browser
3. `services/claim-signer/src/keystore.rs` — where it went
4. `requirements-matrix.md` — everything else, one row at a time
