//! Signature verification, for the two shapes a signature arrives in.
//!
//! A C2PA validator has to check two different kinds of signature with the same
//! set of public keys:
//!
//! - **COSE signatures**, over a claim. RFC 8152 fixes the encoding: ECDSA is
//!   the raw `r || s` pair, fixed width by curve, and RSA is RSASSA-PSS.
//! - **X.509 signatures**, over a `tbsCertificate` or a CMS `SignedAttrs`.
//!   Here ECDSA is DER — `SEQUENCE { r INTEGER, s INTEGER }` — and RSA is
//!   usually PKCS#1 v1.5.
//!
//! Getting the two confused produces a signature that never verifies for
//! reasons that look like a key mismatch, so they are separate entry points
//! rather than one function with a flag.
//!
//! Every algorithm the C2PA specification allows in section 13.2.1 is handled
//! except Ed25519 and the P-521 curve, which are reported as unsupported rather
//! than silently failing: a validator that says "this does not verify" when it
//! means "I cannot check this" is worse than one that admits the gap.

use sha2::{Digest, Sha256, Sha384, Sha512};

use super::identity::alg;
use super::x509::{self, key_oid, sig_oid, Certificate};

#[derive(Debug)]
pub struct VerifyError(String);

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for VerifyError {}

pub type Result<T> = std::result::Result<T, VerifyError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(VerifyError(message.into()))
}

/// Curve OIDs, for matching a key against the algorithm that claims to use it.
const CURVE_P256: &str = "1.2.840.10045.3.1.7";
const CURVE_P384: &str = "1.3.132.0.34";
const CURVE_P521: &str = "1.3.132.0.35";

/// Verify a COSE signature: raw `r || s` for ECDSA, PSS for RSA.
pub fn by_cose_algorithm(
    algorithm: i64,
    certificate: &Certificate,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    match algorithm {
        alg::ES256 => ecdsa_p256(certificate, message, signature, Raw),
        alg::ES384 => ecdsa_p384(certificate, message, signature, Raw),
        alg::ES512 => err("ES512 signatures need the P-521 curve, which this build cannot check"),
        alg::PS256 => rsa_pss(certificate, message, signature, Sha2::S256),
        alg::PS384 => rsa_pss(certificate, message, signature, Sha2::S384),
        alg::PS512 => rsa_pss(certificate, message, signature, Sha2::S512),
        alg::ED25519 => err("Ed25519 signatures cannot be checked by this build"),
        other => err(format!(
            "unsupported signature algorithm {other} ({})",
            alg::name(other)
        )),
    }
}

/// Verify an X.509 or CMS signature made by `issuer` over `message`.
///
/// `algorithm` is the OID from the `AlgorithmIdentifier`.
pub fn by_x509_algorithm(
    algorithm: &str,
    issuer: &Certificate,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    match algorithm {
        sig_oid::ECDSA_SHA256 => ecdsa_p256(issuer, message, signature, Der),
        sig_oid::ECDSA_SHA384 => ecdsa_p384(issuer, message, signature, Der),
        sig_oid::ECDSA_SHA512 => {
            err("ecdsa-with-SHA512 needs the P-521 curve, which this build cannot check")
        }
        sig_oid::RSA_SHA256 => rsa_pkcs1(issuer, message, signature, Sha2::S256),
        sig_oid::RSA_SHA384 => rsa_pkcs1(issuer, message, signature, Sha2::S384),
        sig_oid::RSA_SHA512 => rsa_pkcs1(issuer, message, signature, Sha2::S512),
        // Certificates signed with PSS carry the hash in their parameters. The
        // C2PA profile only allows the SHA-2 family, and salt length equal to
        // the digest is what every conforming CA emits.
        sig_oid::RSASSA_PSS => rsa_pss(issuer, message, signature, Sha2::S256)
            .or_else(|_| rsa_pss(issuer, message, signature, Sha2::S384))
            .or_else(|_| rsa_pss(issuer, message, signature, Sha2::S512)),
        sig_oid::ED25519 => err("Ed25519 certificates cannot be checked by this build"),
        other => err(format!(
            "unsupported certificate signature algorithm {other}"
        )),
    }
}

/// Whether an algorithm is one C2PA 2.2 section 13.2.1 allows at all,
/// regardless of whether this build can check it.
pub fn is_allowed_cose_algorithm(algorithm: i64) -> bool {
    matches!(
        algorithm,
        alg::ES256 | alg::ES384 | alg::ES512 | alg::PS256 | alg::PS384 | alg::PS512 | alg::ED25519
    )
}

/// How an ECDSA signature is encoded.
#[derive(Clone, Copy)]
struct Raw;
#[derive(Clone, Copy)]
struct Der;

trait EcdsaEncoding {
    /// Normalise to the fixed-width `r || s` the `ecdsa` crate expects.
    fn to_fixed(&self, signature: &[u8], coordinate: usize) -> Result<Vec<u8>>;
}

impl EcdsaEncoding for Raw {
    fn to_fixed(&self, signature: &[u8], coordinate: usize) -> Result<Vec<u8>> {
        if signature.len() != coordinate * 2 {
            return err(format!(
                "expected a {}-byte ECDSA signature, got {}",
                coordinate * 2,
                signature.len()
            ));
        }
        Ok(signature.to_vec())
    }
}

impl EcdsaEncoding for Der {
    fn to_fixed(&self, signature: &[u8], coordinate: usize) -> Result<Vec<u8>> {
        let sequence =
            x509::read_tlv(signature).map_err(|e| VerifyError(format!("ECDSA signature: {e}")))?;
        let parts = x509::children(sequence.value)
            .map_err(|e| VerifyError(format!("ECDSA signature: {e}")))?;
        let (Some(r), Some(s)) = (parts.first(), parts.get(1)) else {
            return err("an ECDSA signature must hold two integers");
        };

        let mut out = vec![0u8; coordinate * 2];
        for (index, part) in [r, s].into_iter().enumerate() {
            // DER integers are signed, so a leading zero guards the sign bit.
            let value = part.value.strip_prefix(&[0u8]).unwrap_or(part.value);
            if value.len() > coordinate {
                return err("an ECDSA signature component is too large for the curve");
            }
            let start = index * coordinate + (coordinate - value.len());
            out[start..start + value.len()].copy_from_slice(value);
        }
        Ok(out)
    }
}

fn require_ec_key(certificate: &Certificate, curve: &str, name: &str) -> Result<()> {
    if certificate.public_key_algorithm != key_oid::EC_PUBLIC_KEY {
        return err(format!(
            "{name} needs an elliptic-curve key, but the certificate holds {}",
            certificate.public_key_algorithm
        ));
    }
    // An empty curve means the certificate omitted the named-curve parameter.
    // Accepting it would mean guessing, and a wrong guess reads as a bad
    // signature rather than as the malformed certificate it is.
    if certificate.public_key_curve != curve {
        return err(format!(
            "{name} needs {}, but the certificate's key is on {}",
            curve_name(curve),
            curve_name(&certificate.public_key_curve)
        ));
    }
    Ok(())
}

fn curve_name(oid: &str) -> &str {
    match oid {
        CURVE_P256 => "P-256",
        CURVE_P384 => "P-384",
        CURVE_P521 => "P-521",
        "" => "an unnamed curve",
        other => other,
    }
}

fn ecdsa_p256(
    certificate: &Certificate,
    message: &[u8],
    signature: &[u8],
    encoding: impl EcdsaEncoding,
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;

    require_ec_key(certificate, CURVE_P256, "ES256")?;
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&certificate.public_key)
        .map_err(|e| VerifyError(format!("unusable P-256 key: {e}")))?;
    let fixed = encoding.to_fixed(signature, 32)?;
    let signature = p256::ecdsa::Signature::from_slice(&fixed)
        .map_err(|e| VerifyError(format!("malformed ES256 signature: {e}")))?;
    key.verify(message, &signature)
        .map_err(|_| VerifyError("the signature does not match".into()))
}

fn ecdsa_p384(
    certificate: &Certificate,
    message: &[u8],
    signature: &[u8],
    encoding: impl EcdsaEncoding,
) -> Result<()> {
    use p384::ecdsa::signature::Verifier;

    require_ec_key(certificate, CURVE_P384, "ES384")?;
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&certificate.public_key)
        .map_err(|e| VerifyError(format!("unusable P-384 key: {e}")))?;
    let fixed = encoding.to_fixed(signature, 48)?;
    let signature = p384::ecdsa::Signature::from_slice(&fixed)
        .map_err(|e| VerifyError(format!("malformed ES384 signature: {e}")))?;
    key.verify(message, &signature)
        .map_err(|_| VerifyError("the signature does not match".into()))
}

fn rsa_public_key(certificate: &Certificate) -> Result<rsa::RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey;

    if certificate.public_key_algorithm != key_oid::RSA_ENCRYPTION
        && certificate.public_key_algorithm != key_oid::RSASSA_PSS
    {
        return err(format!(
            "an RSA signature needs an RSA key, but the certificate holds {}",
            certificate.public_key_algorithm
        ));
    }
    rsa::RsaPublicKey::from_pkcs1_der(&certificate.public_key)
        .map_err(|e| VerifyError(format!("unusable RSA key: {e}")))
}

/// Which SHA-2 variant an RSA signature was made with.
#[derive(Clone, Copy, Debug)]
enum Sha2 {
    S256,
    S384,
    S512,
}

fn rsa_pss(certificate: &Certificate, message: &[u8], signature: &[u8], hash: Sha2) -> Result<()> {
    use rsa::signature::Verifier;

    let key = rsa_public_key(certificate)?;
    let signature = rsa::pss::Signature::try_from(signature)
        .map_err(|e| VerifyError(format!("malformed PSS signature: {e}")))?;
    // RFC 8230: the salt is the same length as the digest, which is what
    // `VerifyingKey::new` configures.
    let outcome = match hash {
        Sha2::S256 => rsa::pss::VerifyingKey::<Sha256>::new(key).verify(message, &signature),
        Sha2::S384 => rsa::pss::VerifyingKey::<Sha384>::new(key).verify(message, &signature),
        Sha2::S512 => rsa::pss::VerifyingKey::<Sha512>::new(key).verify(message, &signature),
    };
    outcome.map_err(|_| VerifyError("the signature does not match".into()))
}

fn rsa_pkcs1(
    certificate: &Certificate,
    message: &[u8],
    signature: &[u8],
    hash: Sha2,
) -> Result<()> {
    use rsa::signature::Verifier;

    let key = rsa_public_key(certificate)?;
    let signature = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|e| VerifyError(format!("malformed PKCS#1 signature: {e}")))?;
    let outcome = match hash {
        Sha2::S256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(message, &signature),
        Sha2::S384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key).verify(message, &signature),
        Sha2::S512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key).verify(message, &signature),
    };
    outcome.map_err(|_| VerifyError("the signature does not match".into()))
}

/// SHA-256 of a slice; the digest C2PA uses by default.
pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// Digest a slice with the algorithm a C2PA `alg` field names.
pub fn digest(algorithm: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    Some(match algorithm.to_ascii_lowercase().as_str() {
        "sha256" | "sha-256" => Sha256::digest(bytes).to_vec(),
        "sha384" | "sha-384" => Sha384::digest(bytes).to_vec(),
        "sha512" | "sha-512" => Sha512::digest(bytes).to_vec(),
        _ => return None,
    })
}

/// Digest a slice with the algorithm a DER OID names, for CMS and RFC 3161.
pub fn digest_by_oid(oid: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    Some(match oid {
        "2.16.840.1.101.3.4.2.1" => Sha256::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.2" => Sha384::digest(bytes).to_vec(),
        "2.16.840.1.101.3.4.2.3" => Sha512::digest(bytes).to_vec(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::testpki;

    #[test]
    fn a_raw_cose_signature_verifies() {
        let certificate = x509::parse_certificate(&testpki::leaf_der()).unwrap();
        let message = b"the bytes to be signed";
        let signature = testpki::sign_es256(message);
        by_cose_algorithm(alg::ES256, &certificate, message, &signature).unwrap();
    }

    #[test]
    fn a_der_certificate_signature_verifies() {
        // The leaf's own signature, made by the issuing CA over its TBS bytes.
        let leaf = x509::parse_certificate(&testpki::leaf_der()).unwrap();
        let issuer = x509::parse_certificate(&testpki::issuing_ca_der()).unwrap();
        by_x509_algorithm(
            &leaf.signature_algorithm,
            &issuer,
            &leaf.tbs,
            &leaf.signature,
        )
        .expect("the issuing CA signed this leaf");
    }

    #[test]
    fn the_wrong_issuer_does_not_verify() {
        let leaf = x509::parse_certificate(&testpki::leaf_der()).unwrap();
        let unrelated = x509::parse_certificate(&testpki::tsa_signer_der()).unwrap();
        assert!(by_x509_algorithm(
            &leaf.signature_algorithm,
            &unrelated,
            &leaf.tbs,
            &leaf.signature
        )
        .is_err());
    }

    #[test]
    fn a_flipped_bit_in_the_message_does_not_verify() {
        let certificate = x509::parse_certificate(&testpki::leaf_der()).unwrap();
        let signature = testpki::sign_es256(b"the bytes to be signed");
        assert!(by_cose_algorithm(
            alg::ES256,
            &certificate,
            b"the bytes to be sigped",
            &signature
        )
        .is_err());
    }

    #[test]
    fn a_curve_mismatch_is_named_rather_than_reported_as_a_bad_signature() {
        // A P-256 key presented for ES384 is a setup error, and saying "the
        // signature does not match" would send someone hunting the wrong bug.
        let certificate = x509::parse_certificate(&testpki::leaf_der()).unwrap();
        let error = by_cose_algorithm(alg::ES384, &certificate, b"x", &[0u8; 96]).unwrap_err();
        assert!(error.to_string().contains("P-384"), "{error}");
    }

    #[test]
    fn unsupported_algorithms_say_so_instead_of_failing_silently() {
        let certificate = x509::parse_certificate(&testpki::leaf_der()).unwrap();
        for algorithm in [alg::ED25519, alg::ES512] {
            let error = by_cose_algorithm(algorithm, &certificate, b"x", &[0u8; 64]).unwrap_err();
            assert!(
                error.to_string().contains("cannot") || error.to_string().contains("cannot check"),
                "{error}"
            );
        }
        // But they are still algorithms the specification allows, which is a
        // different question from whether this build can check them.
        assert!(is_allowed_cose_algorithm(alg::ED25519));
        assert!(!is_allowed_cose_algorithm(-99));
    }

    #[test]
    fn der_ecdsa_components_are_left_padded_not_truncated() {
        // A DER integer drops leading zero bytes, so a component shorter than
        // the curve width has to be padded on the left. Right-padding it, or
        // copying it at offset zero, is a bug that only shows up on the roughly
        // one signature in 256 with a short r or s.
        let der = [
            0x30, 0x0A, // SEQUENCE
            0x02, 0x02, 0x00, 0x7F, // r = 0x7F, with the sign guard
            0x02, 0x04, 0x01, 0x02, 0x03, 0x04, // s
        ];
        let fixed = Der.to_fixed(&der, 32).unwrap();
        assert_eq!(fixed.len(), 64);
        assert_eq!(fixed[31], 0x7F);
        assert!(fixed[..31].iter().all(|b| *b == 0));
        assert_eq!(&fixed[60..], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn digest_names_map_to_the_right_lengths() {
        assert_eq!(digest("sha256", b"x").unwrap().len(), 32);
        assert_eq!(digest("sha384", b"x").unwrap().len(), 48);
        assert_eq!(digest("sha512", b"x").unwrap().len(), 64);
        assert!(digest("md5", b"x").is_none());
        assert_eq!(
            digest_by_oid("2.16.840.1.101.3.4.2.1", b"x").unwrap().len(),
            32
        );
        assert!(digest_by_oid("1.3.14.3.2.26", b"x").is_none()); // SHA-1, not allowed
    }
}
