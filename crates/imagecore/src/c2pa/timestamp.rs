//! RFC 3161 time-stamps: reading them, and checking they say what they claim.
//!
//! # Why a browser claim generator needs these now
//!
//! It did not, while the signing certificate was one this repository minted
//! and could date twenty years out. A C2PA claim signing certificate issued
//! under the Certificate Policy at Assurance Level 1 is capped at 366 days,
//! and section 15.8 is unambiguous about what happens next: with no trusted
//! time-stamp, a manifest is judged against the validity window *at the moment
//! someone looks at it*, so every image the editor ever signed would start
//! failing the day the certificate expired.
//!
//! A time-stamp fixes that permanently. Once a validator has a trusted
//! `genTime`, it judges the signing certificate at that instant instead —
//! "this was signed while the certificate was live" stays true forever.
//!
//! Obtaining one is the Backend's job, because it is a network round trip and
//! because RFC 3161 stamps the *signature*, which only the Backend has. What
//! this module does is the reading half: pull the token apart, verify the CMS
//! signature over it, check the imprint really covers this manifest's
//! signature, and hand back the attested time for [`super::trust`] to judge the
//! signing certificate at.
//!
//! # Structure
//!
//! ```text
//!   TimeStampToken = ContentInfo { id-signedData, SignedData }
//!                                                  │
//!        ┌─────────────────────────────────────────┤
//!        │ encapContentInfo: id-ct-TSTInfo, eContent = DER TSTInfo
//!        │ certificates: the TSA's certificate and its issuers
//!        │ signerInfos:  one SignerInfo over the signed attributes
//!        ▼
//!   TSTInfo { version, policy, messageImprint, serialNumber, genTime, ... }
//! ```
//!
//! The signature does not cover `eContent` directly. It covers the DER of the
//! signed attributes, one of which is a digest of `eContent` — so both have to
//! be checked, and checking only the signature is a classic CMS mistake that
//! leaves the payload swappable.

use super::clock::Instant;
use super::trust::{self, Purpose, TrustStore};
use super::verify;
use super::x509::{self, Certificate};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_ATTR_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_ATTR_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

/// Everything a validator needs out of a time-stamp token, once it has been
/// pulled apart but before any of it is believed.
#[derive(Clone, Debug)]
pub struct TimeStamp {
    /// The attested time.
    pub gen_time: Instant,
    /// Digest algorithm OID from `messageImprint`.
    pub imprint_algorithm: String,
    /// The digest the authority says it stamped.
    pub imprint: Vec<u8>,
    /// Certificates the token carried, signer first where it could be
    /// identified.
    pub certificates: Vec<Vec<u8>>,
    /// The TSA's own signing certificate, located by the `SignerInfo`.
    pub signer: Certificate,
}

/// How a time-stamp came out, in the vocabulary section 15.8.2 uses.
///
/// Every failure here is *informational*: an unusable time-stamp is ignored and
/// the manifest falls back to being judged at the current time, rather than
/// being rejected. Getting that wrong would reject good manifests because a TSA
/// changed a certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// `timeStamp.trusted` and `timeStamp.validated`.
    Trusted { at: Instant, authority: String },
    /// `timestamp.malformed`
    Malformed(String),
    /// `timestamp.mismatch`
    Mismatch(String),
    /// `timestamp.untrusted`
    Untrusted(String),
    /// `timestamp.outsideValidity`
    OutsideValidity(String),
}

impl Verdict {
    /// The C2PA status code this verdict is reported under.
    pub fn code(&self) -> &'static str {
        match self {
            Verdict::Trusted { .. } => "timeStamp.validated",
            Verdict::Malformed(_) => "timestamp.malformed",
            Verdict::Mismatch(_) => "timestamp.mismatch",
            Verdict::Untrusted(_) => "timestamp.untrusted",
            Verdict::OutsideValidity(_) => "timestamp.outsideValidity",
        }
    }

    pub fn explanation(&self) -> String {
        match self {
            Verdict::Trusted { at, authority } => format!(
                "time-stamped at {} by {authority}",
                super::clock::to_rfc3339(*at)
            ),
            Verdict::Malformed(why)
            | Verdict::Mismatch(why)
            | Verdict::Untrusted(why)
            | Verdict::OutsideValidity(why) => why.clone(),
        }
    }

    pub fn attested_time(&self) -> Option<Instant> {
        match self {
            Verdict::Trusted { at, .. } => Some(*at),
            _ => None,
        }
    }
}

/// Unwrap an RFC 3161 `TimeStampResp` down to its `timeStampToken`.
///
/// The deprecated `sigTst` header carries the whole response; `sigTst2` carries
/// the token alone.
pub fn token_from_response(der: &[u8]) -> Result<Vec<u8>, String> {
    let outer = x509::read_tlv(der).map_err(|e| e.to_string())?;
    let parts = x509::children(outer.value).map_err(|e| e.to_string())?;
    let status = parts
        .first()
        .ok_or_else(|| "the time-stamp response has no status".to_string())?;
    let status_value = x509::children(status.value)
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .filter(|t| t.tag == TAG_INTEGER)
        .map(|t| {
            t.value
                .iter()
                .fold(0u32, |acc, b| (acc << 8) | u32::from(*b))
        })
        .ok_or_else(|| "the time-stamp response status is unreadable".to_string())?;

    // 0 granted, 1 grantedWithMods. Anything else means the authority declined.
    if status_value > 1 {
        return Err(format!(
            "the time-stamp authority returned PKIStatus {status_value}"
        ));
    }

    let (start, token) = x509::children_with_offsets(outer.value)
        .map_err(|e| e.to_string())?
        .into_iter()
        .nth(1)
        .ok_or_else(|| "the time-stamp response carries no token".to_string())?;
    Ok(outer.value[start..start + token.total].to_vec())
}

/// Read a `TimeStampToken` and verify its own CMS signature.
///
/// This establishes that the authority named inside really signed this
/// `TSTInfo`. It says nothing about whether that authority should be trusted,
/// nor whether the imprint matches anything in particular; [`check`] does both.
pub fn parse(token: &[u8]) -> Result<TimeStamp, String> {
    let content_info = x509::read_tlv(token).map_err(|e| e.to_string())?;
    if content_info.tag != TAG_SEQUENCE {
        return Err("a time-stamp token must be a ContentInfo SEQUENCE".into());
    }
    let ci = x509::children(content_info.value).map_err(|e| e.to_string())?;
    let content_type = ci
        .first()
        .filter(|t| t.tag == TAG_OID)
        .map(|t| x509::oid_to_string(t.value))
        .unwrap_or_default();
    if content_type != OID_SIGNED_DATA {
        return Err(format!(
            "a time-stamp token must hold signedData, not {content_type}"
        ));
    }

    // content [0] EXPLICIT SignedData
    let wrapper = ci
        .get(1)
        .filter(|t| t.tag == 0xA0)
        .ok_or_else(|| "the token has no signedData content".to_string())?;
    let signed_data = x509::read_tlv(wrapper.value).map_err(|e| e.to_string())?;
    let sd = x509::children(signed_data.value).map_err(|e| e.to_string())?;

    // version, digestAlgorithms, encapContentInfo, [0] certificates,
    // [1] crls, signerInfos.
    let encap = sd
        .get(2)
        .filter(|t| t.tag == TAG_SEQUENCE)
        .ok_or_else(|| "the token has no encapContentInfo".to_string())?;
    let encap_parts = x509::children(encap.value).map_err(|e| e.to_string())?;
    let econtent_type = encap_parts
        .first()
        .filter(|t| t.tag == TAG_OID)
        .map(|t| x509::oid_to_string(t.value))
        .unwrap_or_default();
    if econtent_type != OID_TST_INFO {
        return Err(format!(
            "the encapsulated content is {econtent_type}, not a TSTInfo"
        ));
    }
    let econtent_octets = encap_parts
        .get(1)
        .filter(|t| t.tag == 0xA0)
        .and_then(|t| x509::read_tlv(t.value).ok())
        .filter(|t| t.tag == TAG_OCTET_STRING)
        .ok_or_else(|| "the token carries no TSTInfo".to_string())?;
    let tst_info = econtent_octets.value.to_vec();

    let certificates: Vec<Vec<u8>> = sd
        .iter()
        .find(|t| t.tag == 0xA0)
        .map(|set| {
            x509::children_with_offsets(set.value)
                .map(|items| {
                    items
                        .into_iter()
                        .filter(|(_, t)| t.tag == TAG_SEQUENCE)
                        .map(|(start, t)| set.value[start..start + t.total].to_vec())
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();

    let signer_infos = sd
        .iter()
        .rev()
        .find(|t| t.tag == TAG_SET)
        .ok_or_else(|| "the token has no signerInfos".to_string())?;
    let signer_info = x509::children(signer_infos.value)
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| "the token has no SignerInfo".to_string())?;

    let signer = verify_signer_info(signer_info.value, &tst_info, &certificates)?;
    let (gen_time, imprint_algorithm, imprint) = parse_tst_info(&tst_info)?;

    Ok(TimeStamp {
        gen_time,
        imprint_algorithm,
        imprint,
        certificates,
        signer,
    })
}

/// Verify the `SignerInfo`, returning the certificate that made the signature.
fn verify_signer_info(
    bytes: &[u8],
    econtent: &[u8],
    certificates: &[Vec<u8>],
) -> Result<Certificate, String> {
    let parts = x509::children_with_offsets(bytes).map_err(|e| e.to_string())?;
    // version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm,
    // signature, [1] unsignedAttrs.
    let sid = parts
        .get(1)
        .map(|(_, t)| *t)
        .ok_or_else(|| "the SignerInfo has no signer identifier".to_string())?;
    let digest_algorithm = parts
        .get(2)
        .and_then(|(_, t)| x509::children(t.value).ok())
        .and_then(|c| c.first().map(|o| x509::oid_to_string(o.value)))
        .ok_or_else(|| "the SignerInfo has no digest algorithm".to_string())?;

    let signed_attrs = parts.iter().find(|(_, t)| t.tag == 0xA0);

    // The signature algorithm is the last SEQUENCE before the signature OCTET
    // STRING, and the signature is the last OCTET STRING.
    let signature_algorithm = parts
        .iter()
        .rfind(|(_, t)| t.tag == TAG_SEQUENCE)
        .and_then(|(_, t)| x509::children(t.value).ok())
        .and_then(|c| c.first().map(|o| x509::oid_to_string(o.value)))
        .ok_or_else(|| "the SignerInfo has no signature algorithm".to_string())?;
    let signature = parts
        .iter()
        .rfind(|(_, t)| t.tag == TAG_OCTET_STRING)
        .map(|(_, t)| t.value.to_vec())
        .ok_or_else(|| "the SignerInfo has no signature".to_string())?;

    let certificate = locate_signer(sid, certificates)?;

    let Some((attrs_start, attrs)) = signed_attrs.copied() else {
        // Without signed attributes the signature covers eContent directly.
        // Legal in CMS, and RFC 3161 section 2.4.2 does not forbid it.
        return verify::by_x509_algorithm(&signature_algorithm, &certificate, econtent, &signature)
            .map(|()| certificate)
            .map_err(|e| format!("the time-stamp signature does not verify: {e}"));
    };

    // The messageDigest attribute has to match the content, or the signature
    // proves nothing about the TSTInfo that was actually delivered.
    let expected = verify::digest_by_oid(&digest_algorithm, econtent)
        .ok_or_else(|| format!("unsupported digest algorithm {digest_algorithm}"))?;
    let attributes = x509::children(attrs.value).map_err(|e| e.to_string())?;
    let mut saw_content_type = false;
    let mut matched_digest = false;
    for attribute in attributes {
        let fields = x509::children(attribute.value).map_err(|e| e.to_string())?;
        let Some(oid) = fields.first().filter(|t| t.tag == TAG_OID) else {
            continue;
        };
        let oid = x509::oid_to_string(oid.value);
        let value = fields
            .get(1)
            .filter(|t| t.tag == TAG_SET)
            .and_then(|t| x509::children(t.value).ok())
            .and_then(|mut v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v.remove(0))
                }
            });
        match oid.as_str() {
            OID_ATTR_MESSAGE_DIGEST => {
                if let Some(value) = value {
                    matched_digest = value.value == expected.as_slice();
                }
            }
            OID_ATTR_CONTENT_TYPE => saw_content_type = true,
            _ => {}
        }
    }
    if !saw_content_type {
        return Err("the signed attributes omit the content type".into());
    }
    if !matched_digest {
        return Err("the signed message digest does not cover this TSTInfo".into());
    }

    // RFC 5652 section 5.4: the signature covers the signed attributes DER
    // encoded as an explicit SET OF, not with the [0] IMPLICIT tag they carry
    // inside the SignerInfo.
    let mut to_verify = bytes[attrs_start..attrs_start + attrs.total].to_vec();
    to_verify[0] = TAG_SET;

    verify::by_x509_algorithm(&signature_algorithm, &certificate, &to_verify, &signature)
        .map(|()| certificate)
        .map_err(|e| format!("the time-stamp signature does not verify: {e}"))
}

/// Find the certificate a `SignerIdentifier` points at.
fn locate_signer(sid: x509::Tlv<'_>, certificates: &[Vec<u8>]) -> Result<Certificate, String> {
    let parsed: Vec<Certificate> = certificates
        .iter()
        .filter_map(|der| x509::parse_certificate(der).ok())
        .collect();

    match sid.tag {
        // subjectKeyIdentifier [0] IMPLICIT OCTET STRING
        0x80 => parsed
            .into_iter()
            .find(|c| c.subject_key_identifier.as_deref() == Some(sid.value))
            .ok_or_else(|| "the token names a signer it does not carry".to_string()),
        // issuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
        TAG_SEQUENCE => {
            let fields = x509::children_with_offsets(sid.value).map_err(|e| e.to_string())?;
            let (issuer_start, issuer) = *fields
                .first()
                .ok_or_else(|| "the signer identifier has no issuer".to_string())?;
            let issuer_der = sid.value[issuer_start..issuer_start + issuer.total].to_vec();
            let serial = fields
                .get(1)
                .filter(|(_, t)| t.tag == TAG_INTEGER)
                .map(|(_, t)| {
                    t.value
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":")
                })
                .unwrap_or_default();
            parsed
                .into_iter()
                .find(|c| c.issuer_der == issuer_der && c.serial == serial)
                .ok_or_else(|| "the token names a signer it does not carry".to_string())
        }
        other => Err(format!("unsupported signer identifier tag 0x{other:02X}")),
    }
}

/// Pull `genTime` and `messageImprint` out of a `TSTInfo`.
fn parse_tst_info(der: &[u8]) -> Result<(Instant, String, Vec<u8>), String> {
    let sequence = x509::read_tlv(der).map_err(|e| e.to_string())?;
    let fields = x509::children(sequence.value).map_err(|e| e.to_string())?;

    // version, policy, messageImprint, serialNumber, genTime, ...
    let imprint = fields
        .get(2)
        .filter(|t| t.tag == TAG_SEQUENCE)
        .ok_or_else(|| "the TSTInfo has no messageImprint".to_string())?;
    let imprint_parts = x509::children(imprint.value).map_err(|e| e.to_string())?;
    let algorithm = imprint_parts
        .first()
        .and_then(|t| x509::children(t.value).ok())
        .and_then(|c| c.first().map(|o| x509::oid_to_string(o.value)))
        .ok_or_else(|| "the messageImprint has no hash algorithm".to_string())?;
    let hashed = imprint_parts
        .get(1)
        .filter(|t| t.tag == TAG_OCTET_STRING)
        .map(|t| t.value.to_vec())
        .ok_or_else(|| "the messageImprint has no hashed message".to_string())?;

    let gen_time = fields
        .iter()
        .find(|t| t.tag == TAG_GENERALIZED_TIME)
        .and_then(|t| x509::decode_time_instant(t))
        .ok_or_else(|| "the TSTInfo has no readable genTime".to_string())?;

    Ok((gen_time, algorithm, hashed))
}

/// The full section 15.8.2 procedure for one time-stamp.
///
/// `stamped` is the value the imprint should cover: for `sigTst2` that is the
/// `COSE_Sign1` signature field.
pub fn check(token: &[u8], stamped: &[u8], tsa_trust: &TrustStore) -> Verdict {
    let parsed = match parse(token) {
        Ok(parsed) => parsed,
        // A signature that does not verify is a mismatch; anything structural
        // is malformed. `parse` reports the difference in its message.
        Err(why) if why.contains("does not verify") => return Verdict::Mismatch(why),
        Err(why) => return Verdict::Malformed(why),
    };

    let Some(expected) = verify::digest_by_oid(&parsed.imprint_algorithm, stamped) else {
        return Verdict::Untrusted(format!(
            "the imprint uses {}, which is not on the allowed hash list",
            parsed.imprint_algorithm
        ));
    };
    if expected != parsed.imprint {
        return Verdict::Mismatch(
            "the time-stamp covers something other than this signature".into(),
        );
    }

    let outcome = trust::evaluate(
        tsa_trust,
        &parsed.certificates_signer_first(),
        parsed.gen_time,
        Purpose::TimeStamping,
    );
    if !outcome.trusted {
        return Verdict::Untrusted(outcome.reason);
    }
    // Section 15.8.2: the attested time must fall inside the TSA certificate's
    // own window. A time-stamp remains usable after the TSA's certificate
    // expires, which is why this is judged at genTime rather than now.
    if !outcome.inside_validity {
        return Verdict::OutsideValidity(
            "the attested time falls outside the authority's certificate validity".into(),
        );
    }

    Verdict::Trusted {
        at: parsed.gen_time,
        authority: if parsed.signer.subject_common_name.is_empty() {
            parsed.signer.subject.clone()
        } else {
            parsed.signer.subject_common_name.clone()
        },
    }
}

impl TimeStamp {
    /// The token's certificates with the signer at the front, which is the
    /// order path validation expects.
    fn certificates_signer_first(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(self.certificates.len());
        let signer_tbs = &self.signer.tbs;
        for der in &self.certificates {
            match x509::parse_certificate(der) {
                Ok(parsed) if &parsed.tbs == signer_tbs => out.insert(0, der.clone()),
                _ => out.push(der.clone()),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::testpki;

    #[test]
    fn a_token_from_the_test_authority_validates() {
        let stamped = b"a COSE signature, as far as the authority is concerned";
        let token = testpki::issue_timestamp(stamped, testpki::validation_time());
        let (tsa_store, _) = TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap();

        match check(&token, stamped, &tsa_store) {
            Verdict::Trusted { at, authority } => {
                assert_eq!(at, testpki::validation_time());
                assert!(authority.contains("Timestamp Authority"), "{authority}");
            }
            other => panic!("expected a trusted time-stamp, got {other:?}"),
        }
    }

    #[test]
    fn a_token_over_different_bytes_is_a_mismatch() {
        let token = testpki::issue_timestamp(b"one thing", testpki::validation_time());
        let (tsa_store, _) = TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap();
        assert!(matches!(
            check(&token, b"another thing", &tsa_store),
            Verdict::Mismatch(_)
        ));
    }

    #[test]
    fn an_authority_that_is_not_on_the_tsa_list_is_untrusted() {
        let stamped = b"bytes";
        let token = testpki::issue_timestamp(stamped, testpki::validation_time());
        // The claim signing trust list is a real list; it just does not contain
        // the TSA's root.
        let (wrong_store, _) = TrustStore::from_pem(testpki::TRUST_LIST_PEM).unwrap();
        assert!(matches!(
            check(&token, stamped, &wrong_store),
            Verdict::Untrusted(_)
        ));
    }

    #[test]
    fn a_tampered_tst_info_does_not_verify() {
        // The CMS signature covers a digest of the TSTInfo, not the TSTInfo
        // itself, so a validator that checks only the signature would accept a
        // swapped payload. Moving genTime must be caught.
        let stamped = b"bytes";
        let mut token = testpki::issue_timestamp(stamped, testpki::validation_time());
        let needle = b"20";
        // Flip a digit inside the genTime string, wherever it landed.
        let position = token
            .windows(needle.len())
            .rposition(|w| w == needle)
            .expect("the token should contain a GeneralizedTime");
        token[position + 1] ^= 0x01;

        let (tsa_store, _) = TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap();
        assert!(
            !matches!(check(&token, stamped, &tsa_store), Verdict::Trusted { .. }),
            "a modified TSTInfo must not validate"
        );
    }

    #[test]
    fn junk_is_malformed_rather_than_a_panic() {
        let (tsa_store, _) = TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap();
        for junk in [vec![], vec![0x30, 0x00], b"not a token".to_vec()] {
            assert!(matches!(
                check(&junk, b"bytes", &tsa_store),
                Verdict::Malformed(_)
            ));
        }
    }

    #[test]
    fn a_response_wrapper_is_unwrapped_to_its_token() {
        let stamped = b"bytes";
        let token = testpki::issue_timestamp(stamped, testpki::validation_time());
        let response = testpki::wrap_timestamp_response(&token, 0);
        assert_eq!(token_from_response(&response).unwrap(), token);

        // status 2 is "rejection".
        let refused = testpki::wrap_timestamp_response(&token, 2);
        assert!(token_from_response(&refused).is_err());
    }
}
