# Conformance requirements matrix

Every requirement this product has to meet for **Assurance Level 1** under
C2PA Conformance Program v0.2, and where in the repository it is met. The point
of the table is that each row names a file or a command, so a claim can be
checked rather than taken on trust.

Status key:

- **Met** — implemented and covered by a test or a CI step
- **Deployment** — implemented, but the evidence is a property of a running
  deployment rather than of the source
- **Pending** — cannot be done yet, with the reason
- **N/A** — the requirement does not apply, with the reason

---

## Generator Product Security Requirements

### O.1 — Proof of eligibility during automated certificate enrollment

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | Implement the CA's secure authentication method for automated enrollment | N/A | Enrollment is manual through the CA's portal; no GP instance authenticates to a CA. `conformance/enrolment-runbook.md` |
| 2 | Edge binaries SHALL NOT include authentication secrets | Met | No enrollment secret exists anywhere. Enforced in general by `conformance/scripts/check-no-key-material.sh` |
| SE1 | Document the enrollment process and secret management | Met | GPSA §2.1.1 |

### O.2 — Confidentiality of the claim signing key

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | Key encrypted at rest; encrypted in memory except while signing | Met | AES-256-GCM in `services/claim-signer/src/keystore.rs`. Tests: `the_key_is_never_stored_in_the_clear`, `a_tampered_ciphertext_is_refused` |
| 2 | Access to the decrypted key by least privilege | Met | No accessor returns the key; `Keystore::sign` is the only path. File mode `0600`, asserted by `the_sealed_key_is_readable_only_by_its_owner`. Host IAM in GPSA §2.6.1 |
| 3 | Capable of rotating the claim signing key | Met | `claim-signer import` / `activate`. Test: `rotation_stages_a_version_before_switching_to_it` |
| D1 | The Edge API key is used only to limit access to the Backend | Met | `services/claim-signer/src/auth.rs`; it grants nothing but `/v1/sign` |
| D2 | Edge and Backend mutually authenticated, roles validated | Met | HMAC-SHA256 over the request in `auth.rs`; TLS 1.3 server certificate, plus optional mTLS, in `main.rs` |
| D3 | The Backend authenticates the calling client before signing | Met | `sign` authenticates before it parses the body. Tests: the whole `auth::tests` module |
| SE1.1 | Document key access controls | Met | GPSA §2.2.1 |
| SE1.2 | Document the key rotation process | Met | GPSA §2.2.1 (4) |
| SE1.3 | Document ephemeral plaintext key handling | Met | GPSA §2.2.1 (3) |
| SE1.4 | Document subsystem mutual authentication | Met | GPSA §2.2.1 (5) |

### O.3 — Protecting the Claim Generator

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | SCA or SBOM analysis against the NVD | Met | `conformance/scripts/sbom.sh`, `vulnerability-scan.sh`; CI job `supply-chain` |
| 2 | CRITICAL/HIGH fixed or mitigated within 90 days | Met | `conformance/scripts/gate.py` + `vulnerability-ledger.json`; fails the build |
| SE1.1 | Document the scanning tools | Met | GPSA §2.3.1 (1) |
| SE1.2 | Document the pipeline control that prevents late release | Met | GPSA §2.3.1 (2); the control is the gate itself |

### O.4 — Protecting assets and assertions at generation

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | SCA/SBOM for all software that processes content or assertions | Met | Same pipeline; scope is the whole workspace plus the web app |
| 2 | CRITICAL/HIGH fixed within 90 days | Met | Same gate; it does not exempt the image pipeline |

### O.5 — Protecting traffic between subsystems

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | TLS 1.3 or higher between subsystems | Met | `builder_with_protocol_versions(&[&TLS13])` in `services/claim-signer/src/main.rs` — the only version, not a floor |
| SE1 | Document the TLS versions and cipher suites | Met | GPSA §2.5.1 |

### O.6 — Protecting the hosting environment

| # | Requirement | Status | Where |
|---|---|---|---|
| 1 | IAM with RBAC over resources used for generation | Deployment | GPSA §2.6.1 (1)–(3) describes the roles an operator must configure |
| 2 | Vulnerability scanning of dependencies and API surfaces, incl. OWASP Top 10 | Met / Deployment | Dependency scanning is in CI; the API-surface review is GPSA §2.6.1 (4), which answers all ten categories concretely |
| 3 | Basic exploit countermeasures; timely OS and software patching | Deployment | GPSA §2.6.1 (5) |
| SE1 | Document the IAM system and its coverage | Deployment | GPSA §2.6.1 |

---

## Additional Conformance Requirements against the Specification

| Requirement | Applies to | Status | Where |
|---|---|---|---|
| `specVersion` in `claim_generator_info` | 2.4+ | Met | `imagecore::c2pa::SPEC_VERSION`, written for 2.2 as well. Test: `the_claim_declares_the_specification_version_it_was_built_to` |
| `allActionsIncluded` present with a defined value | 2.2 and 2.4 | Met | Always `true` — the editor knows every operation it performed. Test: `the_actions_assertion_declares_that_it_is_complete` |
| `digitalSourceType` in all non-excepted predefined actions | 2.2 and 2.4 | Met | Applied centrally in `actions_for` so a newly added action cannot omit it. Tests: `every_action_that_needs_a_digital_source_type_has_one` (in), `every_action_that_needs_a_digital_source_type_carries_one_in_the_file` (out) |
| `digitalSourceType` prohibited on `c2pa.opened` | 2.4 | Met | Stripped centrally. Test: `c2pa_opened_never_carries_a_digital_source_type` |
| crJSON output from a test harness taking asset, trust list, TSA trust list and validation time | all | Met | `crates/c2pa-harness`; the four flags are the four inputs. Eleven end-to-end tests in `crates/c2pa-harness/tests/harness.rs` |

The `digitalSourceType` value the editor writes is
`http://cv.iptc.org/newscodes/digitalsourcetype/humanEdits` — "augmentation,
correction or enhancement by one or more humans using non-generative tools",
which is exactly what every operation this product offers is. A test asserts
that nothing generative is ever claimed
(`nothing_generative_is_ever_claimed`).

---

## Certificate profile

The certificate comes from a Certification Authority, so these are properties
the product must *read and honour* rather than produce. The test PKI
(`conformance/test-credentials/generate.sh`) issues certificates to the same
profile so every path is exercised before a real certificate exists.

| C2PA Certificate Policy, Claim Signing Leaf — Assurance Level 1 | Handled |
|---|---|
| Validity ≤ 366 days | Parsed to comparable instants; expiry is why time-stamping exists. Test: `assurance_level_1_caps_validity_at_366_days` |
| Key Usage critical: `digitalSignature`, `nonRepudiation` | `x509::key_usage`; `trust::profile_violation` rejects a leaf without `digitalSignature` |
| Basic Constraints critical, `cA=FALSE` | `trust::evaluate` rejects a CA certificate outright — §14.5 forbids one signing a claim |
| EKU: `c2pa-kp-claimSigning` plus `emailProtection` or `documentSigning` | `x509::oid::EKU_CLAIM_SIGNING`; surfaced to the interface via `SignerDescription::claim_signing_eku` |
| `anyExtendedKeyUsage` absent | Rejected by `trust::profile_violation` |
| Certificate Policies contains `1.3.6.1.4.1.62558.1.1` | Parsed into `Certificate::certificate_policies` |
| AIA with an OCSP URI | Parsed into `Certificate::ocsp_responders` |
| `c2pa-al` (1.3.6.1.4.1.62558.3) | Parsed to 1 or 2; shown in the interface and in crJSON |
| `c2pa-cpl-record` (1.3.6.1.4.1.62558.4) | Parsed; shown in the interface and in crJSON |

---

## Specification conformance the tests pin

Not a complete enumeration of the 300-plus normative requirements — that is the
Program's assessment to make — but the ones where getting it wrong produces a
manifest that looks fine and is not.

| Clause | What it requires | Test |
|---|---|---|
| §10.4 | The hard binding excludes exactly the manifest's own bytes | `the_exclusion_range_is_exactly_the_manifest`, `widening_the_exclusion_range_is_rejected` |
| §10.4.2, §10.4.4 | Reserve with `pad`, shrink it to fit, use `pad2` for the sizes `pad` alone cannot express | `padding_hits_the_reserved_size_exactly_for_every_shortfall` |
| §13.2.2 | `x5chain` in the *protected* header; one certificate is a `bstr`, several an array | `the_certificate_chain_is_covered_by_the_signature`, `a_single_certificate_chain_is_a_bare_byte_string` |
| §13.2.3 | Detached payload is `null`, never a zero-length `bstr` | `the_payload_is_detached_rather_than_embedded` |
| §15.7 | Trust path, then signature; algorithm on the allowed list | `a_signer_on_the_trust_list_is_reported_as_trusted`, `a_signer_that_fails_against_a_supplied_trust_list_is_a_failure` |
| §15.8 | A trusted time-stamp moves the instant validity is judged at | `a_time_stamp_keeps_a_credential_valid_after_the_certificate_expires` |
| §15.8.2 | An unusable time-stamp is informational and ignored, not fatal | `a_time_stamp_from_an_untrusted_authority_is_ignored_not_fatal` |
| §15.10.3 | Every referenced assertion present and hashing to the recorded value | `tampering_with_an_assertion_is_caught` |
| §15.10.3.2.2 | `c2pa.opened` resolves to a `parentOf` ingredient | `a_second_edit_chains_onto_the_first` |
| §18.10.2 | `c2pa.opened` is the first action when an asset was opened | `an_opened_file_starts_with_c2pa_opened` |
| RFC 5652 §5.4 | A CMS signature covers the signed attributes as a `SET OF`, and the message digest attribute must cover the payload | `a_tampered_tst_info_does_not_verify` |
