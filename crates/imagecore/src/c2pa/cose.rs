//! `COSE_Sign1` signatures over a C2PA claim (RFC 8152, RFC 9360).
//!
//! What gets signed is not the claim directly but a `Sig_structure` built
//! around it:
//!
//! ```text
//!   Sig_structure = [ "Signature1", body_protected, external_aad, payload ]
//!                     ^^^^^^^^^^^^  ^^^^^^^^^^^^^^  ^^^^^^^^^^^^  ^^^^^^^
//!                     context       the protected   always an     the claim's
//!                                   header, as      empty bstr    serialised
//!                                   encoded bytes   in C2PA       CBOR
//! ```
//!
//! Signing the encoded protected header rather than the header map is what
//! makes the certificate chain tamper-evident: swap the certificate and the
//! signature stops verifying. C2PA requires `x5chain` (label 33) to live in the
//! protected bucket for exactly that reason (section 13.2.2).
//!
//! The result is stored as `COSE_Sign1_Tagged` — CBOR tag 18 — with the payload
//! *detached*. The claim is already sitting in its own JUMBF box a few bytes
//! away, so repeating it inside the signature would only be a second copy that
//! could disagree with the first. Detached means the `payload` field is the
//! simple value `null`; section 13.2.3 is explicit that a zero-length byte
//! string will not do.
//!
//! # Nothing here signs
//!
//! This module builds the bytes to be signed and assembles the result around a
//! signature someone else produced. It holds no key and links no key type. The
//! signature comes back from `services/claim-signer`, which is the only
//! component in the Target of Evaluation that ever sees one — see
//! [`super::identity`] for why that is a conformance requirement rather than a
//! preference.
//!
//! # Padding, and why the unprotected bucket is never empty
//!
//! The hard binding commits to the byte range the manifest occupies, so the
//! signature box's size has to be fixed *before* the signature exists — and
//! before the RFC 3161 time-stamp, whose size nobody can predict, comes back
//! from the TSA. Section 10.4.2 solves this with a zero-filled `pad` in the
//! COSE unprotected header: reserve generously, then shrink `pad` by exactly as
//! much as the real values grew. The unprotected bucket is not covered by the
//! signature, so rewriting it afterwards costs nothing.
//!
//! Section 10.4.4 notes the one wrinkle: deterministic CBOR encodes a byte
//! string's length in a variable number of bytes, so growing `pad` by one byte
//! sometimes grows its encoding by two. The sizes that fall in those cracks are
//! made up with a second field, `pad2`, exactly as the specification prescribes.

use super::cbor::Value;
use super::identity::{alg, SigningIdentity};

/// COSE header label 1: the signature algorithm.
const HEADER_ALG: i64 = 1;
/// COSE header label 33: `x5chain` (RFC 9360). C2PA 2.2 section 13.2.2 says to
/// write the integer label, and that the string form is deprecated.
const HEADER_X5CHAIN: i64 = 33;
/// CBOR tag 18 marks a `COSE_Sign1`.
const TAG_COSE_SIGN1: u64 = 18;

/// Unprotected header labels, all of them string-labelled in C2PA.
const HEADER_SIG_TST2: &str = "sigTst2";
const HEADER_SIG_TST: &str = "sigTst";
const HEADER_PAD: &str = "pad";
const HEADER_PAD2: &str = "pad2";

/// Bytes reserved for an RFC 3161 time-stamp token by default.
///
/// A token signed by an elliptic-curve TSA runs to about 2 KB; one from an RSA
/// authority with a three-deep chain can reach 8. Twelve kilobytes clears both
/// with room to spare, and the Backend overrides it with a figure measured
/// against the TSA actually in use. If a token still will not fit,
/// [`assemble`] says so rather than truncating, and the caller re-prepares with
/// a larger reservation — the retry section 10.4.4 describes.
pub const TIMESTAMP_BUDGET: usize = 12 * 1024;

#[derive(Debug)]
pub struct CoseError(String);

impl std::fmt::Display for CoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CoseError {}

pub type Result<T> = std::result::Result<T, CoseError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(CoseError(message.into()))
}

/// Raised when a time-stamp token is larger than the space reserved for it.
///
/// Named because the caller has a specific remedy — reserve more and prepare
/// again — rather than a generic failure to report.
pub const ERR_RESERVATION_TOO_SMALL: &str = "the signature does not fit the reserved space";

/// The protected header: algorithm plus the certificate chain.
///
/// RFC 9360 says a single certificate is a bare `bstr` and a chain is an array
/// of them. Writing an array of one instead is a common enough mistake that it
/// is worth being explicit about.
fn protected_header(chain: &[Vec<u8>], algorithm: i64) -> Value {
    let x5chain = if chain.len() == 1 {
        Value::bytes(chain[0].clone())
    } else {
        Value::Array(chain.iter().cloned().map(Value::Bytes).collect())
    };

    Value::Map(vec![
        (Value::Uint(HEADER_ALG as u64), Value::NegInt(algorithm)),
        (Value::Uint(HEADER_X5CHAIN as u64), x5chain),
    ])
}

/// The encoded protected header for an identity: the exact bytes the signature
/// will cover.
pub fn protected_bytes(identity: &SigningIdentity) -> Vec<u8> {
    protected_header(&identity.chain, identity.algorithm).encode()
}

/// Build the `Sig_structure` whose encoding is what actually gets signed.
///
/// This is the only thing the Edge subsystem sends to the Backend. It carries
/// the claim, not the image — the picture never leaves the tab.
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::text("Signature1"),
        Value::bytes(protected.to_vec()),
        // C2PA forbids external authenticated data, so this is always empty
        // (section 13.2.3).
        Value::bytes(Vec::new()),
        Value::bytes(payload.to_vec()),
    ])
    .encode()
}

/// The `sigTst2` value: a `tstContainer` holding one DER `TimeStampToken`.
fn tst_container(token: &[u8]) -> Value {
    Value::Map(vec![(
        Value::text("tstTokens"),
        Value::Array(vec![Value::Map(vec![(
            Value::text("val"),
            Value::bytes(token.to_vec()),
        )])]),
    )])
}

/// How many bytes the CBOR head of a byte string of `n` bytes occupies.
fn bstr_head(n: usize) -> usize {
    match n {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        _ => 5,
    }
}

/// The length `pad` must be for its encoded size to grow by `delta` bytes over
/// an empty `pad`, or `None` when no length lands exactly on that figure.
fn pad_length_for(delta: usize) -> Option<usize> {
    if delta == 0 {
        return Some(0);
    }
    // An empty pad encodes as one head byte, so growing to n bytes costs
    // bstr_head(n) + n - 1.
    // head(n) + n == delta + 1, and the head is 1, 2, 3 or 5 bytes, so only
    // four candidate lengths can possibly land on the figure.
    for shrink in [0usize, 1, 2, 4] {
        let n = delta.saturating_sub(shrink);
        if bstr_head(n) + n == delta + 1 {
            return Some(n);
        }
    }
    None
}

/// Choose `pad` and `pad2` lengths that add exactly `need` bytes.
///
/// `need` is measured against a header that already carries an empty `pad`, so
/// the answer for `need == 0` is "leave it empty".
fn padding_for(need: usize) -> Result<(usize, Option<usize>)> {
    if let Some(pad) = pad_length_for(need) {
        return Ok((pad, None));
    }
    // The gaps section 10.4.4 warns about. An empty `pad2` costs six bytes -
    // one map-key head, four for the text, one for the empty byte string - so
    // put six aside for it and land the rest in `pad`.
    const EMPTY_PAD2_COST: usize = 6;
    if need >= EMPTY_PAD2_COST {
        if let Some(pad) = pad_length_for(need - EMPTY_PAD2_COST) {
            return Ok((pad, Some(0)));
        }
    }
    err(format!("no padding combination adds exactly {need} bytes"))
}

/// Assemble a `COSE_Sign1_Tagged` structure with a detached payload.
///
/// `target` is the size the result must be, because the hard binding already
/// committed to it. Pass `None` while measuring, to learn what that size should
/// be.
pub fn assemble(
    protected: &[u8],
    signature: &[u8],
    timestamp: Option<&[u8]>,
    target: Option<usize>,
) -> Result<Vec<u8>> {
    let build = |pad: usize, pad2: Option<usize>| -> Vec<u8> {
        let mut unprotected = Vec::new();
        if let Some(token) = timestamp {
            unprotected.push((Value::text(HEADER_SIG_TST2), tst_container(token)));
        }
        // Always present, even at zero length: section 10.4.2 asks for it, and
        // a fixed shape means the measuring pass and the final pass differ only
        // in the numbers.
        unprotected.push((Value::text(HEADER_PAD), Value::bytes(vec![0u8; pad])));
        if let Some(pad2) = pad2 {
            unprotected.push((Value::text(HEADER_PAD2), Value::bytes(vec![0u8; pad2])));
        }

        Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::bytes(protected.to_vec()),
                Value::Map(unprotected),
                Value::Null,
                Value::bytes(signature.to_vec()),
            ])),
        )
        .encode()
    };

    let minimum = build(0, None);
    let Some(target) = target else {
        return Ok(minimum);
    };

    if minimum.len() > target {
        return err(format!(
            "{ERR_RESERVATION_TOO_SMALL}: {} bytes needed, {target} reserved",
            minimum.len()
        ));
    }

    let (pad, pad2) = padding_for(target - minimum.len())?;
    let padded = build(pad, pad2);
    if padded.len() != target {
        return err(format!(
            "padding produced {} bytes, expected {target}",
            padded.len()
        ));
    }
    Ok(padded)
}

/// The size a signature box must reserve for this identity.
///
/// Everything that varies — the certificate chain, the signature length, the
/// time-stamp budget — is fixed by the identity, so this is exact rather than
/// an estimate, and [`super::manifest`] asserts it rather than trusting it.
pub fn reserved_len(identity: &SigningIdentity) -> Result<usize> {
    let protected = protected_bytes(identity);
    let signature = vec![0u8; identity.signature_len()];
    let token = vec![0u8; identity.timestamp_budget];
    let timestamp = (identity.timestamp_budget > 0).then_some(token.as_slice());
    Ok(assemble(&protected, &signature, timestamp, None)?.len())
}

/// A `COSE_Sign1` of exactly [`reserved_len`] bytes, for sizing the manifest
/// before any of its real values exist.
pub fn placeholder(identity: &SigningIdentity) -> Result<Vec<u8>> {
    let protected = protected_bytes(identity);
    let signature = vec![0u8; identity.signature_len()];
    let token = vec![0u8; identity.timestamp_budget];
    let timestamp = (identity.timestamp_budget > 0).then_some(token.as_slice());
    assemble(&protected, &signature, timestamp, None)
}

/// What a `COSE_Sign1` claims about itself, before any of it is believed.
#[derive(Clone, Debug, Default)]
pub struct ParsedSignature {
    /// DER certificates from `x5chain`, end-entity first.
    pub chain: Vec<Vec<u8>>,
    /// COSE algorithm identifier.
    pub algorithm: i64,
    pub signature: Vec<u8>,
    /// The DER `TimeStampToken` from `sigTst2`, when one is present.
    pub timestamp_token: Option<Vec<u8>>,
    /// True when the deprecated `sigTst` header was used instead, whose value
    /// is a whole `TimeStampResp` rather than a bare token.
    pub timestamp_is_v1: bool,
    /// Set when a time-stamp header carried more than one token, which section
    /// 15.8.1.1 says to report and ignore.
    pub timestamp_ambiguous: bool,
    /// The protected header exactly as encoded — the signature covers these
    /// bytes, so they must be verified as read rather than re-encoded.
    pub protected: Vec<u8>,
}

impl ParsedSignature {
    pub fn algorithm_name(&self) -> &'static str {
        alg::name(self.algorithm)
    }
}

/// Read a `COSE_Sign1_Tagged` without verifying it.
pub fn parse(bytes: &[u8]) -> Result<ParsedSignature> {
    let value = super::cbor::decode(bytes).map_err(|e| CoseError(e.to_string()))?;

    // The tag is required by C2PA, but a signature that is otherwise well
    // formed and merely untagged is still readable, and refusing to display it
    // would be less useful than reporting what it contains.
    let array = match &value {
        Value::Tag(TAG_COSE_SIGN1, inner) => inner.as_array(),
        other => other.as_array(),
    }
    .ok_or_else(|| CoseError("signature is not a COSE_Sign1 array".into()))?;

    if array.len() != 4 {
        return err(format!(
            "COSE_Sign1 has {} elements, expected 4",
            array.len()
        ));
    }

    let protected = array[0]
        .as_bytes()
        .ok_or_else(|| CoseError("protected header is not a byte string".into()))?
        .to_vec();
    let signature = array[3]
        .as_bytes()
        .ok_or_else(|| CoseError("signature is not a byte string".into()))?
        .to_vec();

    // An empty protected bucket is legal CBOR but means no algorithm and no
    // certificate, so there is nothing to verify against.
    let header =
        super::cbor::decode(&protected).map_err(|e| CoseError(format!("protected header: {e}")))?;

    let algorithm = match header.get_int(HEADER_ALG) {
        Some(Value::NegInt(n)) => *n,
        Some(Value::Uint(n)) => *n as i64,
        _ => return err("protected header has no algorithm"),
    };

    let chain = match header.get_int(HEADER_X5CHAIN) {
        Some(Value::Bytes(single)) => vec![single.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_bytes()
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| CoseError("x5chain holds a non-certificate".into()))
            })
            .collect::<Result<Vec<_>>>()?,
        // Validators must also accept the deprecated string label.
        _ => match header.get("x5chain") {
            Some(Value::Bytes(single)) => vec![single.clone()],
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|i| i.as_bytes().map(<[u8]>::to_vec))
                .collect(),
            _ => Vec::new(),
        },
    };

    let mut parsed = ParsedSignature {
        chain,
        algorithm,
        signature,
        protected,
        ..ParsedSignature::default()
    };

    // The unprotected bucket. It is not covered by the signature, so nothing
    // read here is trusted; the time-stamp inside carries its own proof.
    if let Some(container) = array[1].get(HEADER_SIG_TST2) {
        read_timestamp(container, &mut parsed, false);
    } else if let Some(container) = array[1].get(HEADER_SIG_TST) {
        read_timestamp(container, &mut parsed, true);
    }

    Ok(parsed)
}

fn read_timestamp(container: &Value, into: &mut ParsedSignature, v1: bool) {
    let Some(tokens) = container.get("tstTokens").and_then(Value::as_array) else {
        return;
    };
    // Section 15.8.1.1: more than one token is reported and the time-stamps
    // ignored, rather than one being picked arbitrarily.
    if tokens.len() != 1 {
        into.timestamp_ambiguous = true;
        return;
    }
    if let Some(value) = tokens[0].get("val").and_then(Value::as_bytes) {
        into.timestamp_token = Some(value.to_vec());
        into.timestamp_is_v1 = v1;
    }
}

/// Check a parsed signature against the claim it should cover.
///
/// This answers one question only — "was this claim signed by the key in that
/// certificate?" — and deliberately not "should anyone trust that certificate?".
/// The second is [`super::trust`]'s job, because it needs a trust list and a
/// validation time that this function has no business inventing.
pub fn verify(parsed: &ParsedSignature, claim_bytes: &[u8]) -> Result<()> {
    let certificate = parsed
        .chain
        .first()
        .ok_or_else(|| CoseError("no signing certificate in x5chain".into()))?;
    let parsed_certificate =
        super::x509::parse_certificate(certificate).map_err(|e| CoseError(e.to_string()))?;

    let message = sig_structure(&parsed.protected, claim_bytes);
    super::verify::by_cose_algorithm(
        parsed.algorithm,
        &parsed_certificate,
        &message,
        &parsed.signature,
    )
    .map_err(|e| CoseError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::testpki;

    fn sign_with_test_key(identity: &SigningIdentity, claim: &[u8]) -> Vec<u8> {
        let protected = protected_bytes(identity);
        testpki::sign_es256(&sig_structure(&protected, claim))
    }

    #[test]
    fn a_signature_verifies_against_the_claim_it_covers() {
        let identity = testpki::identity_without_timestamps();
        let claim = b"a claim, more or less";
        let signature = sign_with_test_key(&identity, claim);
        let cose = assemble(
            &protected_bytes(&identity),
            &signature,
            None,
            Some(reserved_len(&identity).unwrap()),
        )
        .unwrap();

        let parsed = parse(&cose).unwrap();
        assert_eq!(parsed.algorithm_name(), "ES256");
        assert_eq!(parsed.chain.len(), 2);
        verify(&parsed, claim).expect("the signature should verify");
    }

    #[test]
    fn a_changed_claim_stops_verifying() {
        let identity = testpki::identity_without_timestamps();
        let signature = sign_with_test_key(&identity, b"the original claim");
        let cose = assemble(&protected_bytes(&identity), &signature, None, None).unwrap();
        let parsed = parse(&cose).unwrap();
        assert!(verify(&parsed, b"a different claim").is_err());
    }

    #[test]
    fn the_certificate_chain_is_covered_by_the_signature() {
        // Swapping the chain has to break verification, or x5chain would be a
        // suggestion rather than a binding.
        let identity = testpki::identity_without_timestamps();
        let claim = b"a claim";
        let signature = sign_with_test_key(&identity, claim);

        let mut tampered =
            parse(&assemble(&protected_bytes(&identity), &signature, None, None).unwrap()).unwrap();
        tampered.protected = protected_header(&[testpki::root_ca_der()], alg::ES256).encode();
        assert!(verify(&tampered, claim).is_err());
    }

    #[test]
    fn the_payload_is_detached_rather_than_embedded() {
        // Section 13.2.3: a null payload, never a zero-length byte string.
        let identity = testpki::identity_without_timestamps();
        let cose = assemble(&protected_bytes(&identity), &[0u8; 64], None, None).unwrap();
        let decoded = crate::c2pa::cbor::decode(&cose).unwrap();
        let Value::Tag(18, inner) = &decoded else {
            panic!("expected a tagged COSE_Sign1, got {decoded:?}");
        };
        assert!(matches!(inner.as_array().unwrap()[2], Value::Null));
    }

    #[test]
    fn padding_hits_the_reserved_size_exactly_for_every_shortfall() {
        // The size a time-stamp token comes back at is not predictable, so
        // every possible gap between the real size and the reservation has to
        // be fillable. The two the specification warns about are 24 and 257.
        let identity = testpki::identity_without_timestamps();
        let protected = protected_bytes(&identity);
        let minimum = assemble(&protected, &[0u8; 64], None, None).unwrap().len();

        for extra in 0..600usize {
            let target = minimum + extra;
            let built = assemble(&protected, &[0u8; 64], None, Some(target))
                .unwrap_or_else(|e| panic!("shortfall of {extra} bytes: {e}"));
            assert_eq!(built.len(), target, "shortfall of {extra} bytes");
            // Whatever the padding, the result must still parse.
            parse(&built).unwrap();
        }
    }

    #[test]
    fn a_time_stamp_fits_in_the_space_reserved_for_it() {
        let identity = testpki::identity();
        let reserved = reserved_len(&identity).unwrap();
        assert!(
            reserved > TIMESTAMP_BUDGET,
            "the reservation must cover the token"
        );

        // A token smaller than the budget, which is the normal case.
        let token = vec![0xABu8; 2048];
        let cose = assemble(
            &protected_bytes(&identity),
            &[0u8; 64],
            Some(&token),
            Some(reserved),
        )
        .unwrap();
        assert_eq!(cose.len(), reserved);

        let parsed = parse(&cose).unwrap();
        assert_eq!(parsed.timestamp_token.as_deref(), Some(token.as_slice()));
        assert!(!parsed.timestamp_is_v1);
    }

    #[test]
    fn a_missing_time_stamp_still_fills_the_reservation() {
        // The TSA can be unreachable. The manifest must come out the same size
        // regardless, because the hard binding already committed to it.
        let identity = testpki::identity();
        let reserved = reserved_len(&identity).unwrap();
        let cose = assemble(
            &protected_bytes(&identity),
            &[0u8; 64],
            None,
            Some(reserved),
        )
        .unwrap();
        assert_eq!(cose.len(), reserved);
        assert!(parse(&cose).unwrap().timestamp_token.is_none());
    }

    #[test]
    fn an_oversized_time_stamp_is_reported_rather_than_truncated() {
        let identity = testpki::identity();
        let reserved = reserved_len(&identity).unwrap();
        let token = vec![0u8; identity.timestamp_budget + 4096];
        let error = assemble(
            &protected_bytes(&identity),
            &[0u8; 64],
            Some(&token),
            Some(reserved),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains(ERR_RESERVATION_TOO_SMALL),
            "the caller needs to be told to reserve more, got: {error}"
        );
    }

    #[test]
    fn more_than_one_token_is_flagged_and_ignored() {
        let identity = testpki::identity_without_timestamps();
        let container = Value::Map(vec![(
            Value::text("tstTokens"),
            Value::Array(vec![
                Value::Map(vec![(Value::text("val"), Value::bytes(vec![1, 2, 3]))]),
                Value::Map(vec![(Value::text("val"), Value::bytes(vec![4, 5, 6]))]),
            ]),
        )]);
        let cose = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::bytes(protected_bytes(&identity)),
                Value::Map(vec![(Value::text(HEADER_SIG_TST2), container)]),
                Value::Null,
                Value::bytes(vec![0u8; 64]),
            ])),
        )
        .encode();

        let parsed = parse(&cose).unwrap();
        assert!(parsed.timestamp_ambiguous);
        assert!(parsed.timestamp_token.is_none());
    }

    #[test]
    fn a_single_certificate_chain_is_a_bare_byte_string() {
        // RFC 9360: one certificate is a bstr, several are an array. An array
        // of one is the classic mistake.
        let single = SigningIdentity::new(vec![testpki::leaf_der()], alg::ES256, "k", 0).unwrap();
        let header = crate::c2pa::cbor::decode(&protected_bytes(&single)).unwrap();
        assert!(matches!(
            header.get_int(HEADER_X5CHAIN),
            Some(Value::Bytes(_))
        ));

        let pair = testpki::identity_without_timestamps();
        let header = crate::c2pa::cbor::decode(&protected_bytes(&pair)).unwrap();
        assert!(matches!(
            header.get_int(HEADER_X5CHAIN),
            Some(Value::Array(_))
        ));
    }

    #[test]
    fn rejects_a_structure_that_is_not_a_cose_sign1() {
        assert!(parse(b"").is_err());
        assert!(parse(&Value::Array(vec![Value::Null]).encode()).is_err());
    }
}
