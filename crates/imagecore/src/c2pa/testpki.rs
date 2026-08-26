//! The test PKI, for tests and for the conformance harness. Never for release.
//!
//! Everything in here is behind the `test-pki` feature, which nothing in the
//! shipping WebAssembly build enables. That gate is the point: it is what makes
//! "the Edge subsystem holds no private key" a property the compiler enforces
//! rather than a claim in a document. A release `wasm-pack build` links none of
//! this, and `cargo tree --no-default-features` will show no key type reachable
//! from the library target.
//!
//! The certificates come from `conformance/test-credentials/generate.sh`, which
//! builds them to the same profile the C2PA Certificate Policy defines for a
//! real Assurance Level 1 claim signing certificate. Testing against a
//! correctly shaped certificate is the only way to know the extension parsing,
//! the 366-day expiry handling and the time-stamp fallback all work before a
//! real certificate arrives.

use super::identity::{alg, SigningIdentity};
use super::x509;

pub const CLAIM_SIGNER_CHAIN_PEM: &str =
    include_str!("../../../../conformance/test-credentials/c2pa-test-claim-signer-chain.pem");
pub const CLAIM_SIGNER_KEY_PEM: &str =
    include_str!("../../../../conformance/test-credentials/c2pa-test-claim-signer.key");
pub const ROOT_CA_PEM: &str =
    include_str!("../../../../conformance/test-credentials/c2pa-test-root-ca.pem");
pub const ISSUING_CA_PEM: &str =
    include_str!("../../../../conformance/test-credentials/c2pa-test-issuing-ca.pem");
pub const TRUST_LIST_PEM: &str =
    include_str!("../../../../conformance/test-credentials/c2pa-test-trust-list.pem");
pub const TSA_TRUST_LIST_PEM: &str =
    include_str!("../../../../conformance/test-credentials/c2pa-test-tsa-trust-list.pem");
pub const TSA_SIGNER_PEM: &str =
    include_str!("../../../../conformance/test-credentials/tsa-test-signer.pem");
pub const TSA_SIGNER_KEY_PEM: &str =
    include_str!("../../../../conformance/test-credentials/tsa-test-signer.key");

/// Where the PEM files live, for tests that need to hand a path to a harness.
///
/// `CARGO_MANIFEST_DIR` is `crates/imagecore`, so the repository root is two
/// levels up. Resolved rather than joined blindly, because the path is handed
/// to a subprocess whose working directory is not this one.
pub fn directory() -> std::path::PathBuf {
    let relative =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/test-credentials");
    std::fs::canonicalize(&relative).unwrap_or(relative)
}

fn first(pem: &str) -> Vec<u8> {
    x509::pem_to_der(pem)
        .expect("test PEM should parse")
        .remove(0)
}

pub fn leaf_der() -> Vec<u8> {
    first(CLAIM_SIGNER_CHAIN_PEM)
}

pub fn issuing_ca_der() -> Vec<u8> {
    first(ISSUING_CA_PEM)
}

pub fn root_ca_der() -> Vec<u8> {
    first(ROOT_CA_PEM)
}

pub fn tsa_signer_der() -> Vec<u8> {
    first(TSA_SIGNER_PEM)
}

/// The full `x5chain`: leaf then issuing CA, never the root.
pub fn chain() -> Vec<Vec<u8>> {
    x509::pem_to_der(CLAIM_SIGNER_CHAIN_PEM).expect("test chain should parse")
}

/// A [`SigningIdentity`] over the test chain, with room reserved for a
/// time-stamp so the padded-signature path is the one under test.
pub fn identity() -> SigningIdentity {
    SigningIdentity::new(
        chain(),
        alg::ES256,
        "test-key-1",
        super::cose::TIMESTAMP_BUDGET,
    )
    .expect("the test chain should load as a signing identity")
}

/// The same identity with no time-stamp reservation, for exercising the
/// untimestamped path.
pub fn identity_without_timestamps() -> SigningIdentity {
    SigningIdentity::new(chain(), alg::ES256, "test-key-1", 0)
        .expect("the test chain should load as a signing identity")
}

/// The claim signing key. Exists only in test builds.
pub fn signing_key() -> p256::ecdsa::SigningKey {
    use p256::pkcs8::DecodePrivateKey;
    p256::ecdsa::SigningKey::from_pkcs8_pem(CLAIM_SIGNER_KEY_PEM)
        .expect("the test signing key should load")
}

/// The time-stamping authority's key.
pub fn tsa_key() -> p256::ecdsa::SigningKey {
    use p256::pkcs8::DecodePrivateKey;
    p256::ecdsa::SigningKey::from_pkcs8_pem(TSA_SIGNER_KEY_PEM)
        .expect("the test TSA key should load")
}

/// Sign the way the Backend subsystem would: raw ES256 over the bytes handed
/// in, returning the 64-byte `r || s` a `COSE_Sign1` carries.
pub fn sign_es256(bytes: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = signing_key().sign(bytes);
    signature.to_bytes().to_vec()
}

/// An instant inside the test leaf's validity window.
///
/// The test certificates last 366 days, exactly as the Assurance Level 1
/// profile requires, so a fixed date in a test would start failing a year after
/// someone regenerated them. Deriving the validation time from the certificate
/// keeps the suite honest about expiry without making it a time bomb.
pub fn validation_time() -> i64 {
    let leaf = x509::parse_certificate(&leaf_der()).expect("test leaf should parse");
    leaf.not_before_at + 86_400
}

/// An instant after the test leaf has expired, for the expiry paths.
pub fn after_expiry() -> i64 {
    let leaf = x509::parse_certificate(&leaf_der()).expect("test leaf should parse");
    leaf.not_after_at + 86_400
}

/* -------------------------------------------------------------------------
A stand-in time-stamping authority.

Mocking the time-stamp would have tested the mock. What the validator has to
cope with is a real RFC 3161 token: CMS SignedData wrapping a TSTInfo, signed
over DER-encoded signed attributes rather than over the payload directly.
Issuing one here is about sixty lines and means the parsing, the attribute
handling and the trust path are all exercised by the suite.
------------------------------------------------------------------------- */

use super::der;

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// An arbitrary policy identifier under the test arc.
const OID_TEST_TSA_POLICY: &str = "1.3.6.1.4.1.62558.99.1";

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}

/// Issue an RFC 3161 `TimeStampToken` over `stamped`, attesting `at`.
pub fn issue_timestamp(stamped: &[u8], at: i64) -> Vec<u8> {
    let tst_info = der::sequence(&[
        der::integer(1),               // version
        der::oid(OID_TEST_TSA_POLICY), // policy
        der::sequence(&[
            // messageImprint
            der::algorithm_with_null(OID_SHA256),
            der::octet_string(&sha256(stamped)),
        ]),
        der::integer(1),           // serialNumber
        der::generalized_time(at), // genTime
        der::boolean(false),       // ordering
    ]);

    // RFC 5652 section 5.4: the signature covers the signed attributes encoded
    // as a SET OF, even though they travel under an implicit [0] tag.
    let signed_attrs = der::set_of(&[
        der::sequence(&[
            der::oid(OID_ATTR_CONTENT_TYPE),
            der::set_of(&[der::oid(OID_TST_INFO)]),
        ]),
        der::sequence(&[
            der::oid(OID_ATTR_MESSAGE_DIGEST),
            der::set_of(&[der::octet_string(&sha256(&tst_info))]),
        ]),
    ]);
    let signature = sign_der_ecdsa(&tsa_key(), &signed_attrs);

    let certificate = x509::pem_to_der(TSA_SIGNER_PEM).unwrap().remove(0);
    let signer = x509::parse_certificate(&certificate).unwrap();

    let signer_info = der::sequence(&[
        der::integer(1),
        der::sequence(&[
            signer.issuer_der.clone(),
            der::tlv(0x02, &signer.serial_bytes),
        ]),
        der::algorithm_with_null(OID_SHA256),
        der::implicit_constructed(0, &signed_attrs),
        der::algorithm(OID_ECDSA_SHA256),
        der::octet_string(&signature),
    ]);

    let signed_data = der::sequence(&[
        der::integer(3),
        der::set_of(&[der::algorithm_with_null(OID_SHA256)]),
        der::sequence(&[
            der::oid(OID_TST_INFO),
            der::explicit(0, &der::octet_string(&tst_info)),
        ]),
        der::implicit_constructed(0, &der::set_of(&[certificate])),
        der::set_of(&[signer_info]),
    ]);

    der::sequence(&[der::oid(OID_SIGNED_DATA), der::explicit(0, &signed_data)])
}

/// Wrap a token in the `TimeStampResp` the deprecated `sigTst` header carries.
pub fn wrap_timestamp_response(token: &[u8], status: u64) -> Vec<u8> {
    der::sequence(&[der::sequence(&[der::integer(status)]), token.to_vec()])
}

/// ECDSA over SHA-256 with the DER `SEQUENCE { r, s }` encoding X.509 uses.
fn sign_der_ecdsa(key: &p256::ecdsa::SigningKey, message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = key.sign(message);
    let bytes = signature.to_bytes();
    let (r, s) = bytes.split_at(32);
    der::sequence(&[der_integer(r), der_integer(s)])
}

/// A DER INTEGER from a fixed-width big-endian value.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let trimmed = value
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(value.len() - 1);
    let mut body = value[trimmed..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    der::tlv(0x02, &body)
}
