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
//! Not implemented: RFC 3161 time-stamps (`sigTst2`) and stapled OCSP responses
//! (`rVals`). Both need a network round-trip to a third party at signing time,
//! which an offline browser claim generator cannot do. Their absence is
//! reported honestly to the user rather than papered over — see
//! `signing/README.md` for what it costs.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use super::cbor::Value;

/// COSE header label 1: the signature algorithm.
const HEADER_ALG: i64 = 1;
/// COSE header label 33: `x5chain` (RFC 9360). C2PA 2.2 section 13.2.2 says to
/// write the integer label, and that the string form is deprecated.
const HEADER_X5CHAIN: i64 = 33;
/// COSE algorithm -7: ECDSA with SHA-256.
const ALG_ES256: i64 = -7;
/// CBOR tag 18 marks a `COSE_Sign1`.
const TAG_COSE_SIGN1: u64 = 18;
/// A P-256 signature is r and s, 32 bytes each. Fixed width is what lets the
/// manifest builder reserve space for a signature before producing one.
pub const ES256_SIGNATURE_LEN: usize = 64;

#[derive(Debug)]
pub struct CoseError(String);

impl std::fmt::Display for CoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CoseError {}

type Result<T> = std::result::Result<T, CoseError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(CoseError(message.into()))
}

/// The protected header: algorithm plus the certificate chain.
///
/// RFC 9360 says a single certificate is a bare `bstr` and a chain is an array
/// of them. Writing an array of one instead is a common enough mistake that it
/// is worth being explicit about.
fn protected_header(chain: &[Vec<u8>]) -> Value {
    let x5chain = if chain.len() == 1 {
        Value::bytes(chain[0].clone())
    } else {
        Value::Array(chain.iter().cloned().map(Value::Bytes).collect())
    };

    Value::Map(vec![
        (Value::Uint(HEADER_ALG as u64), Value::NegInt(ALG_ES256)),
        (Value::Uint(HEADER_X5CHAIN as u64), x5chain),
    ])
}

/// Build the `Sig_structure` whose encoding is what actually gets signed.
fn to_be_signed(protected: &[u8], payload: &[u8]) -> Vec<u8> {
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

/// A `COSE_Sign1_Tagged` structure with a detached payload.
fn assemble(protected: &[u8], signature: &[u8]) -> Vec<u8> {
    Value::Tag(
        TAG_COSE_SIGN1,
        Box::new(Value::Array(vec![
            Value::bytes(protected.to_vec()),
            // Unprotected bucket. A time-stamped signature would carry
            // `sigTst2` here; this one has nothing to put in it.
            Value::Map(Vec::new()),
            Value::Null,
            Value::bytes(signature.to_vec()),
        ])),
    )
    .encode()
}

/// Sign `claim_bytes`, returning the serialised `COSE_Sign1_Tagged`.
///
/// The signature is deterministic (RFC 6979), so signing the same claim with
/// the same key twice gives identical bytes. That is not a security property
/// here so much as a practical one: it needs no random number generator, which
/// `wasm32-unknown-unknown` does not have, and it makes tests reproducible.
pub fn sign(claim_bytes: &[u8], key: &SigningKey, chain: &[Vec<u8>]) -> Result<Vec<u8>> {
    if chain.is_empty() {
        return err("cannot sign without a certificate chain");
    }
    let protected = protected_header(chain).encode();
    let signature: Signature = key.sign(&to_be_signed(&protected, claim_bytes));
    let raw = signature.to_bytes();
    debug_assert_eq!(raw.len(), ES256_SIGNATURE_LEN);
    Ok(assemble(&protected, &raw))
}

/// A `COSE_Sign1` produced with a placeholder signature, for sizing.
///
/// The manifest builder has to know how large the signature box will be before
/// it can compute the byte offsets the claim commits to. Because ES256
/// signatures are always 64 bytes and the protected header depends only on the
/// certificate chain, a placeholder is exactly the size of the real thing —
/// which [`crate::c2pa::manifest`] asserts rather than assumes.
pub fn placeholder(chain: &[Vec<u8>]) -> Result<Vec<u8>> {
    if chain.is_empty() {
        return err("cannot size a signature without a certificate chain");
    }
    let protected = protected_header(chain).encode();
    Ok(assemble(&protected, &[0u8; ES256_SIGNATURE_LEN]))
}

/// What a `COSE_Sign1` claims about itself, before any of it is believed.
#[derive(Debug)]
pub struct ParsedSignature {
    /// DER certificates from `x5chain`, end-entity first.
    pub chain: Vec<Vec<u8>>,
    /// COSE algorithm identifier.
    pub algorithm: i64,
    pub signature: Vec<u8>,
    /// The protected header exactly as encoded — the signature covers these
    /// bytes, so they must be verified as read rather than re-encoded.
    protected: Vec<u8>,
}

impl ParsedSignature {
    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            -7 => "ES256",
            -35 => "ES384",
            -36 => "ES512",
            -37 => "PS256",
            -38 => "PS384",
            -39 => "PS512",
            -8 => "EdDSA",
            _ => "unknown",
        }
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

    Ok(ParsedSignature {
        chain,
        algorithm,
        signature,
        protected,
    })
}

/// Check a parsed signature against the claim it should cover.
///
/// This answers one question only — "was this claim signed by the key in that
/// certificate?" — and deliberately not "should anyone trust that certificate?".
/// The second needs a trust anchor store the app does not have.
pub fn verify(parsed: &ParsedSignature, claim_bytes: &[u8]) -> Result<()> {
    if parsed.algorithm != ALG_ES256 {
        return err(format!(
            "unsupported signature algorithm {} ({})",
            parsed.algorithm,
            parsed.algorithm_name()
        ));
    }

    let certificate = parsed
        .chain
        .first()
        .ok_or_else(|| CoseError("no signing certificate in x5chain".into()))?;
    let parsed_certificate =
        super::x509::parse_certificate(certificate).map_err(|e| CoseError(e.to_string()))?;

    let key = VerifyingKey::from_sec1_bytes(&parsed_certificate.public_key)
        .map_err(|e| CoseError(format!("signing certificate has no usable P-256 key: {e}")))?;
    let signature = Signature::from_slice(&parsed.signature)
        .map_err(|e| CoseError(format!("malformed ES256 signature: {e}")))?;

    key.verify(&to_be_signed(&parsed.protected, claim_bytes), &signature)
        .map_err(|_| CoseError("the claim does not match its signature".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::signer;

    fn credentials() -> (SigningKey, Vec<Vec<u8>>) {
        let signer = signer::load().expect("shipped credentials should load");
        (signer.key, signer.chain)
    }

    #[test]
    fn signs_and_verifies_a_claim() {
        let (key, chain) = credentials();
        let claim = b"a claim, pretending to be CBOR";

        let cose = sign(claim, &key, &chain).unwrap();
        let parsed = parse(&cose).unwrap();

        assert_eq!(parsed.algorithm, ALG_ES256);
        assert_eq!(parsed.algorithm_name(), "ES256");
        assert_eq!(parsed.chain.len(), chain.len());
        assert_eq!(parsed.signature.len(), ES256_SIGNATURE_LEN);
        verify(&parsed, claim).expect("a freshly signed claim should verify");
    }

    #[test]
    fn a_changed_claim_fails_verification() {
        let (key, chain) = credentials();
        let cose = sign(b"the original claim", &key, &chain).unwrap();
        let parsed = parse(&cose).unwrap();
        assert!(verify(&parsed, b"the original cIaim").is_err());
    }

    #[test]
    fn a_changed_certificate_fails_verification() {
        // The point of putting x5chain in the *protected* bucket: swapping the
        // certificate has to break the signature, not just the identity.
        let (key, chain) = credentials();
        let claim = b"a claim";
        let cose = sign(claim, &key, &chain).unwrap();
        let mut parsed = parse(&cose).unwrap();

        let root = crate::c2pa::x509::pem_to_der(signer::SIGNING_ROOT_CA_PEM).unwrap();
        parsed.chain = vec![root[0].clone()];
        assert!(
            verify(&parsed, claim).is_err(),
            "verification must not silently use a substituted certificate"
        );
    }

    #[test]
    fn a_flipped_signature_bit_fails_verification() {
        let (key, chain) = credentials();
        let claim = b"a claim";
        let mut parsed = parse(&sign(claim, &key, &chain).unwrap()).unwrap();
        parsed.signature[0] ^= 0x01;
        assert!(verify(&parsed, claim).is_err());
    }

    #[test]
    fn the_payload_is_detached() {
        let (key, chain) = credentials();
        let cose = sign(b"a claim", &key, &chain).unwrap();
        let array = match super::super::cbor::decode(&cose).unwrap() {
            Value::Tag(TAG_COSE_SIGN1, inner) => inner.as_array().unwrap().to_vec(),
            _ => panic!("expected tag 18"),
        };
        assert_eq!(array[2], Value::Null, "detached content must be null");
        assert_ne!(
            array[2],
            Value::bytes(Vec::new()),
            "an empty bstr does not mean detached (section 13.2.3)"
        );
    }

    #[test]
    fn a_single_certificate_is_a_bare_bstr() {
        // RFC 9360: one certificate is a bstr, several are an array of bstr.
        let chain = vec![vec![0xAAu8; 4]];
        let header = super::super::cbor::decode(&protected_header(&chain).encode()).unwrap();
        assert!(matches!(
            header.get_int(HEADER_X5CHAIN),
            Some(Value::Bytes(_))
        ));

        let chain = vec![vec![0xAAu8; 4], vec![0xBBu8; 4]];
        let header = super::super::cbor::decode(&protected_header(&chain).encode()).unwrap();
        assert!(matches!(
            header.get_int(HEADER_X5CHAIN),
            Some(Value::Array(_))
        ));
    }

    #[test]
    fn a_placeholder_is_exactly_the_size_of_a_real_signature() {
        // The manifest builder reserves space using `placeholder` and then
        // writes the real signature into it. If these ever differed, every
        // byte offset in the hard binding would be wrong.
        let (key, chain) = credentials();
        let real = sign(b"a claim of some length", &key, &chain).unwrap();
        assert_eq!(placeholder(&chain).unwrap().len(), real.len());
    }

    #[test]
    fn signing_is_deterministic() {
        // RFC 6979. No RNG needed, which matters on wasm32-unknown-unknown.
        let (key, chain) = credentials();
        assert_eq!(
            sign(b"a claim", &key, &chain).unwrap(),
            sign(b"a claim", &key, &chain).unwrap()
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse(b"not cbor at all").is_err());
        // A four-element array is required.
        assert!(parse(&Value::Array(vec![Value::Null]).encode()).is_err());
        // No algorithm in the protected header.
        let headerless = Value::Tag(
            TAG_COSE_SIGN1,
            Box::new(Value::Array(vec![
                Value::bytes(Value::Map(Vec::new()).encode()),
                Value::Map(Vec::new()),
                Value::Null,
                Value::bytes(vec![0u8; 64]),
            ])),
        );
        assert!(parse(&headerless.encode()).is_err());
    }
}
