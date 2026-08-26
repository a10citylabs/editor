//! Enough DER to read, and to check, a signing certificate.
//!
//! This grew from "report what the certificate says" into a real certificate
//! parser, because the C2PA Conformance Program needs both halves of the job:
//!
//! - The **claim generator** side reads the leaf to learn who is signing, at
//!   what Assurance Level, and under which Conforming Products List record.
//!   Those three facts live in extensions the C2PA Certificate Policy defines
//!   (`c2pa-al`, `c2pa-cpl-record`, `c2pa-kp-claimSigning`) and nowhere else.
//! - The **validator** side needs everything RFC 5280 path validation touches:
//!   the `tbsCertificate` bytes and signature so a chain can be verified, names
//!   in their raw DER form so issuers can be matched exactly, validity as
//!   comparable instants, key usage, basic constraints, and the key identifiers
//!   that make chain building cheap.
//!
//! What is *not* here is any policy. This module answers "what does this
//! certificate contain"; [`super::trust`] decides what to make of it.

use std::fmt;

use super::clock::{self, Instant};

#[derive(Debug)]
pub struct DerError(String);

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed certificate: {}", self.0)
    }
}

impl std::error::Error for DerError {}

type Result<T> = std::result::Result<T, DerError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(DerError(message.into()))
}

/* ---- DER tags ---- */
const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;

/// One tag-length-value triple.
///
/// Public because the DER this crate parses does not stop at certificates: the
/// claim-signer service reads RFC 3161 responses with the same primitives, and
/// a second copy of a DER reader is a second place for a length-handling bug to
/// live.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    /// Total encoded size, so a caller can step to the next element. Paired
    /// with the offsets [`children_with_offsets`] returns, this is how a caller
    /// slices an element back out byte for byte - which matters for anything
    /// re-derived over the exact encoding, like a `tbsCertificate`.
    pub total: usize,
}

pub fn read_tlv(bytes: &[u8]) -> Result<Tlv<'_>> {
    let tag = *bytes
        .first()
        .ok_or_else(|| DerError("input ended".into()))?;
    let first_len = *bytes
        .get(1)
        .ok_or_else(|| DerError("length byte missing".into()))?;

    let (len, header) = if first_len & 0x80 == 0 {
        (first_len as usize, 2)
    } else {
        let count = (first_len & 0x7F) as usize;
        // Long form. More than four length bytes would mean a certificate
        // bigger than 4GB, which is not a thing anyone should be parsing.
        if count == 0 || count > 4 {
            return err("unsupported DER length encoding");
        }
        let slice = bytes
            .get(2..2 + count)
            .ok_or_else(|| DerError("length runs past the end".into()))?;
        let mut len = 0usize;
        for byte in slice {
            len = (len << 8) | *byte as usize;
        }
        (len, 2 + count)
    };

    let value = bytes
        .get(header..header + len)
        .ok_or_else(|| DerError(format!("value of {len} bytes runs past the end")))?;

    Ok(Tlv {
        tag,
        value,
        total: header + len,
    })
}

/// Split a constructed value into its elements.
pub fn children(bytes: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let tlv = read_tlv(&bytes[at..])?;
        at += tlv.total;
        out.push(tlv);
    }
    Ok(out)
}

/// Like [`children`], but also hands back where each element started, for
/// callers that need the exact encoded bytes of an element.
pub fn children_with_offsets(bytes: &[u8]) -> Result<Vec<(usize, Tlv<'_>)>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let tlv = read_tlv(&bytes[at..])?;
        let start = at;
        at += tlv.total;
        out.push((start, tlv));
    }
    Ok(out)
}

/// Dotted-decimal form of an OID, for comparison and display.
pub fn oid_to_string(bytes: &[u8]) -> String {
    let Some((&first, rest)) = bytes.split_first() else {
        return String::new();
    };
    // The first byte packs two arcs: 40 * arc1 + arc2.
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut value: u64 = 0;
    for byte in rest {
        value = (value << 7) | u64::from(byte & 0x7F);
        if byte & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
        }
    }
    out
}

pub fn decode_string(tlv: &Tlv<'_>) -> String {
    match tlv.tag {
        TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING => {
            String::from_utf8_lossy(tlv.value).into_owned()
        }
        // BMPString and friends are UTF-16BE. Rare in practice; decoding them
        // loosely beats showing mojibake. A trailing odd byte is dropped, which
        // `as_chunks` gives for free by returning only the whole pairs.
        0x1E => tlv
            .value
            .as_chunks::<2>()
            .0
            .iter()
            .filter_map(|pair| char::from_u32(u32::from(u16::from_be_bytes(*pair))))
            .collect(),
        _ => String::from_utf8_lossy(tlv.value).into_owned(),
    }
}

/// `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ` rendered as an ISO-8601 date.
fn decode_time(tlv: &Tlv<'_>) -> String {
    let raw = String::from_utf8_lossy(tlv.value);
    match decode_time_instant(tlv) {
        Some(instant) => clock::to_rfc3339(instant),
        None => raw.into_owned(),
    }
}

pub fn decode_time_instant(tlv: &Tlv<'_>) -> Option<Instant> {
    let raw = String::from_utf8_lossy(tlv.value);
    match tlv.tag {
        TAG_UTC_TIME => clock::parse_asn1_time(&raw, true),
        TAG_GENERALIZED_TIME => clock::parse_asn1_time(&raw, false),
        _ => None,
    }
}

/* ---- Attribute and extension OIDs ---- */
const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ORGANISATION: &str = "2.5.4.10";
const OID_ORGANISATIONAL_UNIT: &str = "2.5.4.11";
const OID_COUNTRY: &str = "2.5.4.6";
const OID_STATE: &str = "2.5.4.8";
const OID_LOCALITY: &str = "2.5.4.7";
const OID_SERIAL_NUMBER_ATTR: &str = "2.5.4.5";

const OID_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_CERTIFICATE_POLICIES: &str = "2.5.29.32";
const OID_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
const OID_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
const OID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// OIDs from the C2PA private arc, as the C2PA Certificate Policy v0.2 defines
/// them.
pub mod oid {
    /// `c2pa-kp-claimSigning`, the extended key usage a C2PA claim signing
    /// certificate must assert.
    pub const EKU_CLAIM_SIGNING: &str = "1.3.6.1.4.1.62558.2.1";
    /// `id-c2pa-al`, whose value is the assurance level OID.
    pub const ASSURANCE_LEVEL: &str = "1.3.6.1.4.1.62558.3";
    pub const ASSURANCE_LEVEL_1: &str = "1.3.6.1.4.1.62558.3.10";
    pub const ASSURANCE_LEVEL_2: &str = "1.3.6.1.4.1.62558.3.20";
    /// `c2pa-cpl-record`, a UTF8String holding the Conforming Products List
    /// record UUID.
    pub const CPL_RECORD: &str = "1.3.6.1.4.1.62558.4";
    /// `c2pa-certificate-policy`.
    pub const CERTIFICATE_POLICY: &str = "1.3.6.1.4.1.62558.1.1";
}

/// Public key algorithm OIDs.
pub mod key_oid {
    pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    pub const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
    pub const ED25519: &str = "1.3.101.112";
}

/// Signature algorithm OIDs, as they appear in `AlgorithmIdentifier`.
pub mod sig_oid {
    pub const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
    pub const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
    pub const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
    pub const RSA_SHA256: &str = "1.2.840.113549.1.1.11";
    pub const RSA_SHA384: &str = "1.2.840.113549.1.1.12";
    pub const RSA_SHA512: &str = "1.2.840.113549.1.1.13";
    pub const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
    pub const ED25519: &str = "1.3.101.112";
}

/// Human-readable names for the EKUs C2PA cares about.
fn eku_name(oid: &str) -> &str {
    match oid {
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.36" => "documentSigning",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        "2.5.29.37.0" => "anyExtendedKeyUsage",
        oid::EKU_CLAIM_SIGNING => "c2pa-kp-claimSigning",
        other => other,
    }
}

/// `KeyUsage` bits, in the order RFC 5280 assigns them.
pub mod key_usage {
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    pub const NON_REPUDIATION: u16 = 1 << 1;
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    pub const CRL_SIGN: u16 = 1 << 6;
}

/// One relative distinguished name, kept as a pair so crJSON can render the
/// whole DN as an object rather than a flattened string.
pub type NameAttribute = (String, String);

/// What a certificate says about itself.
#[derive(Clone, Debug, Default)]
pub struct Certificate {
    pub subject: String,
    pub subject_common_name: String,
    pub subject_organisation: String,
    pub subject_attributes: Vec<NameAttribute>,
    pub issuer: String,
    pub issuer_common_name: String,
    pub issuer_attributes: Vec<NameAttribute>,
    pub not_before: String,
    pub not_after: String,
    pub not_before_at: Instant,
    pub not_after_at: Instant,
    pub serial: String,
    /// The serial number's DER integer content, for re-encoding it into a CMS
    /// `issuerAndSerialNumber`. Certification authorities issue serials of up
    /// to twenty octets, which no integer type here would hold.
    pub serial_bytes: Vec<u8>,
    /// SEC1 public key point for EC keys, or the DER `RSAPublicKey` body for
    /// RSA. [`Certificate::public_key_algorithm`] says which.
    pub public_key: Vec<u8>,
    /// Public key algorithm OID.
    pub public_key_algorithm: String,
    /// Named-curve OID from the key's `AlgorithmIdentifier` parameters, for EC
    /// keys. Without it a P-384 key looks like a malformed P-256 one.
    pub public_key_curve: String,
    pub extended_key_usage: Vec<String>,
    pub extended_key_usage_oids: Vec<String>,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub key_usage: Option<u16>,
    pub subject_key_identifier: Option<Vec<u8>>,
    pub authority_key_identifier: Option<Vec<u8>>,
    pub certificate_policies: Vec<String>,
    pub ocsp_responders: Vec<String>,
    /// The value of `c2pa-al`, reduced to 1 or 2.
    pub c2pa_assurance_level: Option<u32>,
    /// The value of `c2pa-cpl-record`.
    pub c2pa_cpl_record_id: Option<String>,
    /// Critical extensions this parser did not recognise. RFC 5280 requires a
    /// path validator to reject a certificate carrying one of these rather
    /// than ignore it.
    pub unrecognised_critical_extensions: Vec<String>,

    /* -- the raw material path validation needs -- */
    /// DER of `tbsCertificate`, exactly as encoded: what the issuer signed.
    pub tbs: Vec<u8>,
    /// DER of the subject `Name`, for exact issuer/subject matching.
    pub subject_der: Vec<u8>,
    /// DER of the issuer `Name`.
    pub issuer_der: Vec<u8>,
    /// The certificate's own signature.
    pub signature: Vec<u8>,
    /// OID of the algorithm that signature was made with.
    pub signature_algorithm: String,
    /// DER of the outer `signatureAlgorithm` field, needed for RSASSA-PSS
    /// where the parameters carry the hash and salt length.
    pub signature_algorithm_params: Vec<u8>,
}

impl Certificate {
    /// Whether the leaf asserts `c2pa-kp-claimSigning`.
    pub fn has_claim_signing_eku(&self) -> bool {
        self.extended_key_usage_oids
            .iter()
            .any(|o| o == oid::EKU_CLAIM_SIGNING)
    }

    pub fn has_eku(&self, oid: &str) -> bool {
        self.extended_key_usage_oids.iter().any(|o| o == oid)
    }

    /// Whether the subject and issuer names are byte-identical, which is what
    /// makes a certificate a candidate trust anchor.
    pub fn is_self_issued(&self) -> bool {
        !self.subject_der.is_empty() && self.subject_der == self.issuer_der
    }

    pub fn allows(&self, usage: u16) -> bool {
        // RFC 5280: an absent KeyUsage places no restriction.
        self.key_usage.is_none_or(|bits| bits & usage != 0)
    }

    /// Size in bytes of an RSA modulus, or `None` for a non-RSA key. This is
    /// how large a PS256/PS384/PS512 signature will be.
    pub fn rsa_modulus_bytes(&self) -> Option<usize> {
        if self.public_key_algorithm != key_oid::RSA_ENCRYPTION
            && self.public_key_algorithm != key_oid::RSASSA_PSS
        {
            return None;
        }
        let sequence = read_tlv(&self.public_key).ok()?;
        let modulus = children(sequence.value).ok()?.into_iter().next()?;
        // DER integers carry a leading zero byte when the high bit is set.
        Some(modulus.value.len() - usize::from(modulus.value.first() == Some(&0)))
    }
}

/// A distinguished name, rendered like OpenSSL's `subject=` line, plus its
/// attributes as pairs.
fn parse_name(bytes: &[u8]) -> Result<(String, String, String, Vec<NameAttribute>)> {
    let mut parts = Vec::new();
    let mut attributes = Vec::new();
    let mut common_name = String::new();
    let mut organisation = String::new();

    for rdn in children(bytes)? {
        if rdn.tag != TAG_SET {
            continue;
        }
        for attribute in children(rdn.value)? {
            if attribute.tag != TAG_SEQUENCE {
                continue;
            }
            let pair = children(attribute.value)?;
            let (Some(oid), Some(value)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            if oid.tag != TAG_OID {
                continue;
            }
            let oid = oid_to_string(oid.value);
            let text = decode_string(value);
            let label = match oid.as_str() {
                OID_COMMON_NAME => "CN",
                OID_ORGANISATION => "O",
                OID_ORGANISATIONAL_UNIT => "OU",
                OID_COUNTRY => "C",
                OID_STATE => "ST",
                OID_LOCALITY => "L",
                OID_SERIAL_NUMBER_ATTR => "serialNumber",
                other => other,
            };
            match label {
                "CN" => common_name = text.clone(),
                "O" => organisation = text.clone(),
                _ => {}
            }
            parts.push(format!("{label} = {text}"));
            attributes.push((label.to_string(), text));
        }
    }

    Ok((parts.join(", "), common_name, organisation, attributes))
}

/// Read a DER-encoded X.509 certificate.
pub fn parse_certificate(der: &[u8]) -> Result<Certificate> {
    let certificate = read_tlv(der)?;
    if certificate.tag != TAG_SEQUENCE {
        return err("a certificate must be a SEQUENCE");
    }
    let body = certificate.value;
    let top = children_with_offsets(body)?;
    let (tbs_start, tbs) = *top
        .first()
        .filter(|(_, t)| t.tag == TAG_SEQUENCE)
        .ok_or_else(|| DerError("missing tbsCertificate".into()))?;

    let mut out = Certificate {
        tbs: body[tbs_start..tbs_start + tbs.total].to_vec(),
        ..Certificate::default()
    };

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    if let Some((start, algorithm)) = top.get(1) {
        out.signature_algorithm_params = body[*start..*start + algorithm.total].to_vec();
        out.signature_algorithm = children(algorithm.value)?
            .first()
            .filter(|o| o.tag == TAG_OID)
            .map(|o| oid_to_string(o.value))
            .unwrap_or_default();
    }
    if let Some((_, signature)) = top.get(2) {
        if signature.tag == TAG_BIT_STRING {
            out.signature = signature.value.get(1..).unwrap_or_default().to_vec();
        }
    }

    let fields = children_with_offsets(tbs.value)?;
    let mut at = 0;

    // version [0] EXPLICIT, present for v3 and absent for v1.
    if fields.first().map(|(_, f)| f.tag) == Some(0xA0) {
        at = 1;
    }

    if let Some((_, field)) = fields.get(at).filter(|(_, f)| f.tag == TAG_INTEGER) {
        out.serial_bytes = field.value.to_vec();
        out.serial = field
            .value
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
    }
    at += 1;
    at += 1; // signature AlgorithmIdentifier, repeated inside the TBS

    let (issuer_start, issuer) = *fields
        .get(at)
        .ok_or_else(|| DerError("missing issuer".into()))?;
    let (issuer_name, issuer_cn, _, issuer_attributes) = parse_name(issuer.value)?;
    out.issuer = issuer_name;
    out.issuer_common_name = issuer_cn;
    out.issuer_attributes = issuer_attributes;
    out.issuer_der = tbs.value[issuer_start..issuer_start + issuer.total].to_vec();
    at += 1;

    let (_, validity) = *fields
        .get(at)
        .ok_or_else(|| DerError("missing validity".into()))?;
    let times = children(validity.value)?;
    out.not_before = times.first().map(decode_time).unwrap_or_default();
    out.not_after = times.get(1).map(decode_time).unwrap_or_default();
    out.not_before_at = times.first().and_then(decode_time_instant).unwrap_or(0);
    // An unreadable notAfter must not read as "valid forever".
    out.not_after_at = times.get(1).and_then(decode_time_instant).unwrap_or(0);
    at += 1;

    let (subject_start, subject) = *fields
        .get(at)
        .ok_or_else(|| DerError("missing subject".into()))?;
    let (subject_name, subject_cn, subject_org, subject_attributes) = parse_name(subject.value)?;
    out.subject = subject_name;
    out.subject_common_name = subject_cn;
    out.subject_organisation = subject_org;
    out.subject_attributes = subject_attributes;
    out.subject_der = tbs.value[subject_start..subject_start + subject.total].to_vec();
    at += 1;

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let (_, spki) = *fields
        .get(at)
        .ok_or_else(|| DerError("missing subjectPublicKeyInfo".into()))?;
    let spki_parts = children(spki.value)?;
    let algorithm_parts = spki_parts
        .first()
        .map(|a| children(a.value))
        .transpose()?
        .unwrap_or_default();
    out.public_key_algorithm = algorithm_parts
        .first()
        .filter(|o| o.tag == TAG_OID)
        .map(|o| oid_to_string(o.value))
        .unwrap_or_default();
    out.public_key_curve = algorithm_parts
        .get(1)
        .filter(|o| o.tag == TAG_OID)
        .map(|o| oid_to_string(o.value))
        .unwrap_or_default();
    let key_bits = spki_parts
        .get(1)
        .filter(|k| k.tag == TAG_BIT_STRING)
        .ok_or_else(|| DerError("public key is not a BIT STRING".into()))?;
    // A BIT STRING leads with a count of unused trailing bits, always zero for
    // a key, and the key itself follows.
    out.public_key = key_bits.value.get(1..).unwrap_or_default().to_vec();
    at += 1;

    // Optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
    for (_, field) in fields.iter().skip(at) {
        if field.tag != 0xA3 {
            continue;
        }
        let Some(sequence) = children(field.value)?.into_iter().next() else {
            continue;
        };
        for extension in children(sequence.value)? {
            read_extension(extension.value, &mut out)?;
        }
    }

    Ok(out)
}

fn read_extension(bytes: &[u8], out: &mut Certificate) -> Result<()> {
    let parts = children(bytes)?;
    let Some(oid) = parts.first().filter(|o| o.tag == TAG_OID) else {
        return Ok(());
    };
    let oid = oid_to_string(oid.value);
    let critical = parts
        .iter()
        .any(|p| p.tag == TAG_BOOLEAN && p.value.first() == Some(&0xFF));
    // `critical` is optional and defaults to false, so the OCTET STRING is
    // whichever of the remaining elements has that tag.
    let Some(payload) = parts.iter().find(|p| p.tag == TAG_OCTET_STRING) else {
        return Ok(());
    };

    match oid.as_str() {
        OID_EXTENDED_KEY_USAGE => {
            if let Ok(sequence) = read_tlv(payload.value) {
                for entry in children(sequence.value)? {
                    if entry.tag == TAG_OID {
                        let dotted = oid_to_string(entry.value);
                        out.extended_key_usage.push(eku_name(&dotted).to_string());
                        out.extended_key_usage_oids.push(dotted);
                    }
                }
            }
        }
        OID_BASIC_CONSTRAINTS => {
            if let Ok(sequence) = read_tlv(payload.value) {
                for entry in children(sequence.value)? {
                    match entry.tag {
                        TAG_BOOLEAN => out.is_ca = entry.value.first() == Some(&0xFF),
                        TAG_INTEGER => {
                            let mut value = 0u32;
                            for byte in entry.value {
                                value = (value << 8) | u32::from(*byte);
                            }
                            out.path_len = Some(value);
                        }
                        _ => {}
                    }
                }
            }
        }
        OID_KEY_USAGE => {
            // KeyUsage ::= BIT STRING, big-endian with bit 0 leftmost.
            if let Ok(bits) = read_tlv(payload.value) {
                let unused = usize::from(*bits.value.first().unwrap_or(&0));
                let mut mask = 0u16;
                for (index, byte) in bits.value.iter().skip(1).enumerate() {
                    for bit in 0..8 {
                        let position = index * 8 + bit;
                        if index == bits.value.len() - 2 && bit >= 8 - unused.min(8) {
                            break;
                        }
                        if byte & (0x80 >> bit) != 0 && position < 16 {
                            mask |= 1 << position;
                        }
                    }
                }
                out.key_usage = Some(mask);
            }
        }
        OID_SUBJECT_KEY_IDENTIFIER => {
            if let Ok(octets) = read_tlv(payload.value) {
                out.subject_key_identifier = Some(octets.value.to_vec());
            }
        }
        OID_AUTHORITY_KEY_IDENTIFIER => {
            if let Ok(sequence) = read_tlv(payload.value) {
                // keyIdentifier is [0] IMPLICIT OCTET STRING.
                for entry in children(sequence.value)? {
                    if entry.tag == 0x80 {
                        out.authority_key_identifier = Some(entry.value.to_vec());
                    }
                }
            }
        }
        OID_CERTIFICATE_POLICIES => {
            if let Ok(sequence) = read_tlv(payload.value) {
                for policy in children(sequence.value)? {
                    if let Some(id) = children(policy.value)?.first().filter(|o| o.tag == TAG_OID) {
                        out.certificate_policies.push(oid_to_string(id.value));
                    }
                }
            }
        }
        OID_AUTHORITY_INFO_ACCESS => {
            if let Ok(sequence) = read_tlv(payload.value) {
                for description in children(sequence.value)? {
                    let parts = children(description.value)?;
                    let method = parts
                        .first()
                        .filter(|o| o.tag == TAG_OID)
                        .map(|o| oid_to_string(o.value))
                        .unwrap_or_default();
                    // accessLocation is a GeneralName; uniformResourceIdentifier
                    // is context tag [6].
                    if method == OID_AD_OCSP {
                        if let Some(location) = parts.get(1).filter(|l| l.tag == 0x86) {
                            out.ocsp_responders
                                .push(String::from_utf8_lossy(location.value).into_owned());
                        }
                    }
                }
            }
        }
        oid::ASSURANCE_LEVEL => {
            if let Ok(value) = read_tlv(payload.value) {
                if value.tag == TAG_OID {
                    out.c2pa_assurance_level = match oid_to_string(value.value).as_str() {
                        oid::ASSURANCE_LEVEL_1 => Some(1),
                        oid::ASSURANCE_LEVEL_2 => Some(2),
                        _ => None,
                    };
                }
            }
        }
        oid::CPL_RECORD => {
            if let Ok(value) = read_tlv(payload.value) {
                out.c2pa_cpl_record_id = Some(decode_string(&value));
            }
        }
        other => {
            if critical {
                out.unrecognised_critical_extensions.push(other.to_string());
            }
        }
    }

    Ok(())
}

/// Pull every DER body out of a PEM document, in order.
///
/// Written by hand rather than pulled from a crate because it is twenty lines
/// and the alternative is another dependency in a WebAssembly bundle.
pub fn pem_to_der(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut base64 = String::new();
    let mut inside = false;

    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            inside = true;
            base64.clear();
        } else if line.starts_with("-----END") {
            if inside {
                out.push(base64_decode(&base64)?);
            }
            inside = false;
        } else if inside {
            base64.push_str(line);
        }
    }

    if out.is_empty() {
        return err("no PEM blocks found");
    }
    Ok(out)
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits = 0;

    for byte in input.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let Some(value) = sextet(byte) else {
            return err("invalid base64 in PEM body");
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::testpki;

    fn leaf() -> Certificate {
        parse_certificate(&testpki::leaf_der()).unwrap()
    }

    #[test]
    fn reads_the_test_claim_signing_certificate() {
        let cert = leaf();
        assert_eq!(cert.subject_common_name, "A10city Image Editor");
        assert_eq!(cert.subject_organisation, "A10city Labs");
        assert!(!cert.issuer.is_empty());
        assert_ne!(
            cert.issuer, cert.subject,
            "the leaf must not be self-signed"
        );
        assert!(!cert.serial.is_empty());
        assert!(!cert.is_self_issued());
    }

    #[test]
    fn extracts_a_usable_p256_public_key() {
        let cert = leaf();
        // Uncompressed SEC1 point: 0x04 then two 32-byte coordinates.
        assert_eq!(cert.public_key.len(), 65);
        assert_eq!(cert.public_key[0], 0x04);
        assert_eq!(cert.public_key_algorithm, key_oid::EC_PUBLIC_KEY);
        assert_eq!(cert.public_key_curve, "1.2.840.10045.3.1.7"); // prime256v1
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.public_key)
            .expect("the parsed key should load");
    }

    #[test]
    fn reads_the_c2pa_certificate_policy_extensions() {
        // These three are what separate a certificate issued under the C2PA
        // Certificate Policy from any other signing certificate, and the whole
        // conformance story rests on reading them correctly.
        let cert = leaf();
        assert_eq!(cert.c2pa_assurance_level, Some(1));
        assert_eq!(
            cert.c2pa_cpl_record_id.as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert!(cert.has_claim_signing_eku());
        assert!(cert
            .certificate_policies
            .iter()
            .any(|p| p == oid::CERTIFICATE_POLICY));
    }

    #[test]
    fn the_leaf_matches_the_assurance_level_1_profile() {
        let cert = leaf();
        assert!(!cert.is_ca, "cA must be FALSE on a claim signing leaf");
        assert!(cert.allows(key_usage::DIGITAL_SIGNATURE));
        assert!(cert.allows(key_usage::NON_REPUDIATION));
        assert!(!cert.allows(key_usage::KEY_CERT_SIGN));
        assert!(
            !cert.has_eku("2.5.29.37.0"),
            "anyExtendedKeyUsage is forbidden"
        );
        assert!(
            cert.extended_key_usage_oids
                .iter()
                .any(|o| o == "1.3.6.1.5.5.7.3.4" || o == "1.3.6.1.5.5.7.3.36"),
            "the profile requires emailProtection or documentSigning alongside claimSigning"
        );
        assert!(
            !cert.ocsp_responders.is_empty(),
            "AIA with an OCSP URI is required"
        );
        assert!(cert.subject_key_identifier.is_some());
        assert!(cert.authority_key_identifier.is_some());
    }

    #[test]
    fn assurance_level_1_caps_validity_at_366_days() {
        let cert = leaf();
        let span = cert.not_after_at - cert.not_before_at;
        assert!(span > 0);
        assert!(
            span <= 366 * 86_400,
            "a level 1 leaf may not be valid for longer than 366 days, got {} days",
            span / 86_400
        );
    }

    #[test]
    fn reads_validity_dates_as_iso_8601_and_as_instants() {
        let cert = leaf();
        assert!(
            cert.not_before.len() == 20 && cert.not_before.ends_with('Z'),
            "unexpected notBefore {:?}",
            cert.not_before
        );
        assert!(cert.not_after > cert.not_before);
        assert_eq!(
            crate::c2pa::clock::to_rfc3339(cert.not_before_at),
            cert.not_before
        );
    }

    #[test]
    fn recognises_the_certificate_authorities() {
        let root = parse_certificate(&testpki::root_ca_der()).unwrap();
        assert!(root.is_ca);
        assert!(root.is_self_issued(), "the root should be self-signed");
        assert!(root.allows(key_usage::KEY_CERT_SIGN));

        let issuing = parse_certificate(&testpki::issuing_ca_der()).unwrap();
        assert!(issuing.is_ca);
        assert_eq!(issuing.path_len, Some(0));
        assert!(!issuing.is_self_issued());
    }

    #[test]
    fn the_tbs_bytes_are_the_exact_slice_the_issuer_signed() {
        // If this is off by so much as the header, every chain verification
        // fails with a signature mismatch that looks like a key problem.
        let der = testpki::leaf_der();
        let cert = parse_certificate(&der).unwrap();
        let outer = read_tlv(&der).unwrap();
        let tbs = read_tlv(outer.value).unwrap();
        assert_eq!(cert.tbs.len(), tbs.total);
        assert_eq!(cert.tbs, &outer.value[..tbs.total]);
    }

    #[test]
    fn issuer_and_subject_names_match_byte_for_byte_across_the_chain() {
        let leaf = leaf();
        let issuing = parse_certificate(&testpki::issuing_ca_der()).unwrap();
        assert_eq!(leaf.issuer_der, issuing.subject_der);
        assert_eq!(
            leaf.authority_key_identifier,
            issuing.subject_key_identifier
        );
    }

    #[test]
    fn the_timestamp_authority_asserts_only_time_stamping() {
        let tsa = parse_certificate(&testpki::tsa_signer_der()).unwrap();
        assert_eq!(tsa.extended_key_usage_oids, vec!["1.3.6.1.5.5.7.3.8"]);
    }

    #[test]
    fn oid_encoding_round_trips() {
        // 1.2.840.10045.2.1, id-ecPublicKey.
        let der = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        assert_eq!(oid_to_string(&der), "1.2.840.10045.2.1");
    }

    #[test]
    fn rejects_junk() {
        assert!(parse_certificate(&[0x30, 0x00]).is_err());
        assert!(parse_certificate(b"not a certificate").is_err());
        assert!(pem_to_der("no pem here").is_err());
    }
}
