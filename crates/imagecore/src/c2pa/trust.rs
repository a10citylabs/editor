//! Trust anchors, and the path validation that uses them.
//!
//! Section 15.7 of the specification splits the question a validator answers
//! into two, and the split matters:
//!
//! - **Is the signature intact?** [`super::cose::verify`] answers that from the
//!   certificate in `x5chain` alone. It needs nothing external.
//! - **Should anyone believe the certificate?** That needs a trust anchor list
//!   and a validation time, and this module is where both arrive.
//!
//! An earlier version of this engine could only answer the first, and said so
//! honestly. That is no longer enough: the Conformance Program requires a
//! Generator Product with validation functionality to produce crJSON results
//! against a supplied C2PA Trust List and TSA Trust List at a supplied
//! validation time. Those three inputs are exactly the arguments here.
//!
//! # What is checked
//!
//! Chain building is by exact issuer/subject `Name` match with the Authority
//! Key Identifier as a hint, then RFC 5280 path validation reduced to the
//! checks that bear on a C2PA claim signature:
//!
//! | Check | Why |
//! |---|---|
//! | signature of each certificate by its issuer | the chain is otherwise decorative |
//! | validity window at the validation time | section 15.8 makes the time-stamp decide this |
//! | `cA` on every CA, and *not* on the leaf | section 14.5: a CA certificate may never sign a claim |
//! | `pathLenConstraint` | an issuing CA that says it issues no CAs must be held to it |
//! | `keyCertSign` on every CA | RFC 5280 §6.1.4 |
//! | unrecognised critical extensions | RFC 5280 §6.1.3: reject rather than ignore |
//!
//! Revocation is not checked. C2PA treats a stapled OCSP response as the way to
//! carry revocation status, and the specification says the manifest is judged
//! on the response captured at signing time; there is no live OCSP fetch to
//! make from a browser tab, and an absent response is `signingCredential.ocsp.
//! skipped` rather than a failure. What is *not* done is pretending otherwise.

use super::clock::Instant;
use super::verify;
use super::x509::{self, key_usage, Certificate};

/// A list of trust anchors, as a C2PA Trust List or TSA Trust List supplies
/// them: a bundle of PEM certificates.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    anchors: Vec<Certificate>,
}

impl TrustStore {
    /// An empty store. Every chain evaluated against it is untrusted, which is
    /// the correct answer when no list has been configured, and the reported
    /// status code says which of the two situations produced it.
    pub fn empty() -> Self {
        TrustStore::default()
    }

    /// Load anchors from a PEM bundle.
    ///
    /// Certificates that will not parse are skipped rather than fatal: a trust
    /// list is a long concatenation maintained by someone else, and one bad
    /// entry should not disable the other three hundred. The count of what
    /// loaded is returned so a caller can report the difference.
    pub fn from_pem(pem: &str) -> Result<(Self, usize), String> {
        let ders = x509::pem_to_der(pem).map_err(|e| e.to_string())?;
        let total = ders.len();
        let anchors: Vec<Certificate> = ders
            .iter()
            .filter_map(|der| x509::parse_certificate(der).ok())
            .collect();
        let skipped = total - anchors.len();
        Ok((TrustStore { anchors }, skipped))
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Anchors whose subject matches the issuer of `certificate`.
    fn issuers_of<'a>(&'a self, certificate: &Certificate) -> Vec<&'a Certificate> {
        self.anchors
            .iter()
            .filter(|anchor| anchor.subject_der == certificate.issuer_der)
            .filter(|anchor| {
                match (
                    &certificate.authority_key_identifier,
                    &anchor.subject_key_identifier,
                ) {
                    // When both sides carry a key identifier they must agree; a
                    // matching name with a different key is a different CA that
                    // happens to share a name, which does happen after a rekey.
                    (Some(akid), Some(skid)) => akid == skid,
                    _ => true,
                }
            })
            .collect()
    }
}

/// What the chain is being used for, which decides the profile checks applied
/// to the leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A C2PA claim signature.
    ClaimSigning,
    /// An RFC 3161 time-stamp token.
    TimeStamping,
}

/// The outcome of evaluating one chain.
#[derive(Clone, Debug, Default)]
pub struct ChainOutcome {
    /// Whether a path to an anchor was built and every certificate on it
    /// verified.
    pub trusted: bool,
    /// Whether every certificate on the path was inside its validity window at
    /// the validation time. Reported separately because section 15.8 lets a
    /// time-stamp move the instant this is judged at.
    pub inside_validity: bool,
    /// The trust anchor the path reached, when it reached one.
    pub anchor: Option<String>,
    /// Why the evaluation came out the way it did, for the explanation field of
    /// the status code.
    pub reason: String,
    /// The full path, leaf first, anchor last.
    pub path: Vec<Certificate>,
}

impl ChainOutcome {
    fn rejected(reason: impl Into<String>) -> Self {
        ChainOutcome {
            reason: reason.into(),
            ..ChainOutcome::default()
        }
    }
}

/// Build and validate a path from `chain` to an anchor in `store`.
///
/// `chain` is the `x5chain` as it arrived: end-entity first, intermediates
/// after, trust anchor absent. `at` is the instant validity is judged at — the
/// time-stamp's attested time when there is a trusted one, otherwise the
/// validation time.
pub fn evaluate(
    store: &TrustStore,
    chain: &[Vec<u8>],
    at: Instant,
    purpose: Purpose,
) -> ChainOutcome {
    let Some(leaf_der) = chain.first() else {
        return ChainOutcome::rejected("the signature carries no certificate");
    };
    let leaf = match x509::parse_certificate(leaf_der) {
        Ok(leaf) => leaf,
        Err(e) => {
            return ChainOutcome::rejected(format!("the signing certificate is malformed: {e}"))
        }
    };

    // Section 14.5: only end-entity certificates sign claims and time-stamps.
    // A CA certificate here is a rejection, not a warning.
    if leaf.is_ca {
        return ChainOutcome::rejected(
            "the signing certificate is a CA certificate, which may not sign claims",
        );
    }
    if let Some(reason) = profile_violation(&leaf, purpose) {
        return ChainOutcome::rejected(reason);
    }

    let intermediates: Vec<Certificate> = chain[1..]
        .iter()
        .filter_map(|der| x509::parse_certificate(der).ok())
        .collect();

    let mut path = vec![leaf];
    let mut inside_validity = true;

    // Walk up through the intermediates the signature supplied, then look for
    // an anchor. Depth is bounded so a chain that loops back on itself cannot
    // spin: eight is far past anything a real hierarchy uses.
    const MAX_DEPTH: usize = 8;
    for depth in 0..MAX_DEPTH {
        let current = path.last().expect("the path always holds the leaf");
        inside_validity &= at >= current.not_before_at && at <= current.not_after_at;

        if !current.unrecognised_critical_extensions.is_empty() {
            return ChainOutcome::rejected(format!(
                "{} carries a critical extension this validator does not understand ({})",
                describe(current),
                current.unrecognised_critical_extensions.join(", ")
            ));
        }

        // An anchor terminates the path. Its own signature is not checked:
        // a trust anchor is trusted because it is on the list, not because it
        // vouches for itself.
        if let Some(anchor) = store.issuers_of(current).into_iter().next() {
            if let Err(e) = verify_issued_by(current, anchor) {
                return ChainOutcome::rejected(format!(
                    "{} does not verify against the trust anchor {}: {e}",
                    describe(current),
                    describe(anchor)
                ));
            }
            inside_validity &= at >= anchor.not_before_at && at <= anchor.not_after_at;
            let name = describe(anchor);
            path.push(anchor.clone());
            return ChainOutcome {
                trusted: true,
                inside_validity,
                anchor: Some(name.clone()),
                reason: format!("the chain reaches the trust anchor {name}"),
                path,
            };
        }

        // A self-issued certificate that is not on the list is the end of the
        // road: there is nothing above it to find.
        if current.is_self_issued() {
            return ChainOutcome {
                trusted: false,
                inside_validity,
                anchor: None,
                reason: format!(
                    "the chain ends at {}, which is self-signed and not on the trust list",
                    describe(current)
                ),
                path,
            };
        }

        let Some(issuer) = intermediates
            .iter()
            .find(|candidate| candidate.subject_der == current.issuer_der)
        else {
            return ChainOutcome {
                trusted: false,
                inside_validity,
                anchor: None,
                reason: format!(
                    "no certificate for the issuer of {} is on the trust list or in the chain",
                    describe(current)
                ),
                path,
            };
        };

        if !issuer.is_ca {
            return ChainOutcome::rejected(format!(
                "{} is not a CA certificate but issued {}",
                describe(issuer),
                describe(current)
            ));
        }
        if !issuer.allows(key_usage::KEY_CERT_SIGN) {
            return ChainOutcome::rejected(format!(
                "{} does not assert keyCertSign",
                describe(issuer)
            ));
        }
        // pathLenConstraint counts the non-self-issued intermediates below
        // this CA. `depth` is how many we have already walked past.
        if let Some(limit) = issuer.path_len {
            if depth as u32 > limit {
                return ChainOutcome::rejected(format!(
                    "{} allows a path of {limit}, but the chain is longer",
                    describe(issuer)
                ));
            }
        }
        if let Err(e) = verify_issued_by(current, issuer) {
            return ChainOutcome::rejected(format!(
                "{} does not verify against {}: {e}",
                describe(current),
                describe(issuer)
            ));
        }

        path.push(issuer.clone());
    }

    ChainOutcome::rejected("the certificate chain is longer than this validator will follow")
}

/// Profile checks that depend on what the leaf is for.
fn profile_violation(leaf: &Certificate, purpose: Purpose) -> Option<String> {
    // anyExtendedKeyUsage is forbidden on a C2PA signing certificate whichever
    // way it is being used (section 14.4.1).
    if leaf.has_eku("2.5.29.37.0") {
        return Some(format!(
            "{} asserts anyExtendedKeyUsage, which a C2PA signing certificate may not",
            describe(leaf)
        ));
    }
    if !leaf.allows(key_usage::DIGITAL_SIGNATURE) {
        return Some(format!(
            "{} does not assert digitalSignature",
            describe(leaf)
        ));
    }
    match purpose {
        Purpose::ClaimSigning => {
            if leaf.extended_key_usage_oids.is_empty() {
                return Some(format!(
                    "{} carries no extended key usage, which section 14.4.1 requires",
                    describe(leaf)
                ));
            }
        }
        Purpose::TimeStamping => {
            // RFC 3161 section 2.3.
            if !leaf.has_eku("1.3.6.1.5.5.7.3.8") {
                return Some(format!(
                    "{} does not assert the timeStamping extended key usage",
                    describe(leaf)
                ));
            }
        }
    }
    None
}

fn verify_issued_by(subject: &Certificate, issuer: &Certificate) -> verify::Result<()> {
    verify::by_x509_algorithm(
        &subject.signature_algorithm,
        issuer,
        &subject.tbs,
        &subject.signature,
    )
}

fn describe(certificate: &Certificate) -> String {
    if certificate.subject_common_name.is_empty() {
        certificate.subject.clone()
    } else {
        certificate.subject_common_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::testpki;

    fn store() -> TrustStore {
        TrustStore::from_pem(testpki::TRUST_LIST_PEM).unwrap().0
    }

    #[test]
    fn a_chain_to_a_listed_anchor_is_trusted() {
        let outcome = evaluate(
            &store(),
            &testpki::chain(),
            testpki::validation_time(),
            Purpose::ClaimSigning,
        );
        assert!(outcome.trusted, "{}", outcome.reason);
        assert!(outcome.inside_validity);
        // Leaf, issuing CA, root.
        assert_eq!(outcome.path.len(), 3);
        assert!(outcome.anchor.as_deref().unwrap().contains("Root CA"));
    }

    #[test]
    fn an_empty_trust_list_trusts_nothing() {
        let outcome = evaluate(
            &TrustStore::empty(),
            &testpki::chain(),
            testpki::validation_time(),
            Purpose::ClaimSigning,
        );
        assert!(!outcome.trusted);
        assert!(outcome.reason.contains("trust list"), "{}", outcome.reason);
    }

    #[test]
    fn a_chain_to_the_wrong_anchor_is_untrusted() {
        // The TSA list is a perfectly good trust list; it just does not contain
        // this signer's root.
        let (tsa_store, _) = TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap();
        let outcome = evaluate(
            &tsa_store,
            &testpki::chain(),
            testpki::validation_time(),
            Purpose::ClaimSigning,
        );
        assert!(!outcome.trusted);
    }

    #[test]
    fn a_missing_intermediate_is_untrusted_rather_than_assumed() {
        let outcome = evaluate(
            &store(),
            &testpki::chain()[..1],
            testpki::validation_time(),
            Purpose::ClaimSigning,
        );
        assert!(!outcome.trusted);
        assert!(outcome.reason.contains("issuer"), "{}", outcome.reason);
    }

    #[test]
    fn expiry_is_reported_separately_from_trust() {
        // A time-stamp can rescue an expired certificate, so "the chain is
        // sound" and "it was inside its window at this instant" have to be two
        // answers rather than one.
        let outcome = evaluate(
            &store(),
            &testpki::chain(),
            testpki::after_expiry(),
            Purpose::ClaimSigning,
        );
        assert!(outcome.trusted, "{}", outcome.reason);
        assert!(!outcome.inside_validity);
    }

    #[test]
    fn a_ca_certificate_may_not_sign_a_claim() {
        let chain = vec![testpki::issuing_ca_der(), testpki::root_ca_der()];
        let outcome = evaluate(
            &store(),
            &chain,
            testpki::validation_time(),
            Purpose::ClaimSigning,
        );
        assert!(!outcome.trusted);
        assert!(
            outcome.reason.contains("CA certificate"),
            "{}",
            outcome.reason
        );
    }

    #[test]
    fn a_tampered_certificate_does_not_verify_against_its_issuer() {
        let mut chain = testpki::chain();
        // Flip a byte in the leaf's TBS. The DER stays well formed enough to
        // parse - the byte is inside the subject common name - but the issuing
        // CA's signature no longer covers it.
        let leaf = &mut chain[0];
        let at = leaf.len() / 3;
        leaf[at] ^= 0x01;
        let outcome = evaluate(
            &store(),
            &chain,
            testpki::validation_time(),
            Purpose::ClaimSigning,
        );
        assert!(!outcome.trusted, "{}", outcome.reason);
    }

    #[test]
    fn the_timestamp_authority_needs_the_time_stamping_usage() {
        let (tsa_store, _) = TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap();
        let outcome = evaluate(
            &tsa_store,
            &[testpki::tsa_signer_der()],
            testpki::validation_time(),
            Purpose::TimeStamping,
        );
        assert!(outcome.trusted, "{}", outcome.reason);

        // The claim signer, which has no timeStamping usage, must not pass as
        // a time-stamping authority.
        let outcome = evaluate(
            &store(),
            &testpki::chain(),
            testpki::validation_time(),
            Purpose::TimeStamping,
        );
        assert!(!outcome.trusted);
        assert!(
            outcome.reason.contains("timeStamping"),
            "{}",
            outcome.reason
        );
    }

    #[test]
    fn a_trust_list_with_junk_in_it_still_loads_the_rest() {
        let mixed = format!(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n{}",
            testpki::TRUST_LIST_PEM
        );
        let (store, skipped) = TrustStore::from_pem(&mixed).unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(store.len(), 1);
    }
}
