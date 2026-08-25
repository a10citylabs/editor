//! Just enough DER to look inside a signing certificate.
//!
//! Two things are needed from the `x5chain` header: the public key, so a
//! signature can actually be checked, and enough human-readable detail — who
//! this is, who vouched for them, until when — for the UI to say something
//! truthful about the signer.
//!
//! This is deliberately *not* a certificate validator. It does not walk chains,
//! check revocation, or decide whether anyone should be trusted; those need a
//! trust anchor store and a clock, and the app has neither. What it does is
//! report what the certificate says about itself, so the interface can show it
//! next to a clear statement that nobody has vouched for it. Section 14.5.1's
//! profile rules are enforced at certificate *generation* time instead — see
//! `signing/generate.sh`.

use std::fmt;

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
#[derive(Clone, Copy, Debug)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// Total encoded size, so a caller can step to the next element.
    total: usize,
}

fn read_tlv(bytes: &[u8]) -> Result<Tlv<'_>> {
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
fn children(bytes: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let tlv = read_tlv(&bytes[at..])?;
        at += tlv.total;
        out.push(tlv);
    }
    Ok(out)
}

/// Dotted-decimal form of an OID, for comparison and display.
fn oid_to_string(bytes: &[u8]) -> String {
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

fn decode_string(tlv: &Tlv<'_>) -> String {
    match tlv.tag {
        TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING => {
            String::from_utf8_lossy(tlv.value).into_owned()
        }
        // BMPString and friends are UTF-16BE. Rare in practice; decoding them
        // loosely beats showing mojibake.
        0x1E => tlv
            .value
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>()
            .iter()
            .filter_map(|c| char::from_u32(u32::from(*c)))
            .collect(),
        _ => String::from_utf8_lossy(tlv.value).into_owned(),
    }
}

/// `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ` rendered as an ISO-8601 date.
fn decode_time(tlv: &Tlv<'_>) -> String {
    let raw = String::from_utf8_lossy(tlv.value);
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();

    let (year, rest) = match tlv.tag {
        TAG_UTC_TIME if digits.len() >= 10 => {
            let two: u32 = digits[..2].parse().unwrap_or(0);
            // RFC 5280: 00-49 means 20xx, 50-99 means 19xx.
            let year = if two < 50 { 2000 + two } else { 1900 + two };
            (year, &digits[2..])
        }
        TAG_GENERALIZED_TIME if digits.len() >= 12 => {
            (digits[..4].parse().unwrap_or(0), &digits[4..])
        }
        _ => return raw.into_owned(),
    };

    if rest.len() < 8 {
        return raw.into_owned();
    }
    format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        rest.get(8..10).unwrap_or("00"),
    )
}

/* ---- Attribute and extension OIDs ---- */
const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_ORGANISATION: &str = "2.5.4.10";
const OID_ORGANISATIONAL_UNIT: &str = "2.5.4.11";
const OID_COUNTRY: &str = "2.5.4.6";
const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";

/// Human-readable names for the EKUs C2PA cares about (section 14.4.1).
fn eku_name(oid: &str) -> &str {
    match oid {
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.36" => "documentSigning",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        "2.5.29.37.0" => "anyExtendedKeyUsage",
        other => other,
    }
}

/// What a certificate says about itself.
#[derive(Clone, Debug, Default)]
pub struct Certificate {
    pub subject: String,
    pub subject_common_name: String,
    pub subject_organisation: String,
    pub issuer: String,
    pub issuer_common_name: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    /// SEC1 public key point, ready for `p256`.
    pub public_key: Vec<u8>,
    /// Public key algorithm OID.
    pub public_key_algorithm: String,
    pub extended_key_usage: Vec<String>,
    pub is_ca: bool,
}

/// A distinguished name, rendered like OpenSSL's `subject=` line.
fn parse_name(bytes: &[u8]) -> Result<(String, String, String)> {
    let mut parts = Vec::new();
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
                _ => continue,
            };
            if oid == OID_COMMON_NAME {
                common_name = text.clone();
            }
            if oid == OID_ORGANISATION {
                organisation = text.clone();
            }
            parts.push(format!("{label}={text}"));
        }
    }

    Ok((parts.join(", "), common_name, organisation))
}

/// Read a DER-encoded X.509 certificate.
pub fn parse_certificate(der: &[u8]) -> Result<Certificate> {
    let certificate = read_tlv(der)?;
    if certificate.tag != TAG_SEQUENCE {
        return err("a certificate must be a SEQUENCE");
    }
    let top = children(certificate.value)?;
    let tbs = top
        .first()
        .filter(|t| t.tag == TAG_SEQUENCE)
        .ok_or_else(|| DerError("missing tbsCertificate".into()))?;

    let fields = children(tbs.value)?;
    let mut at = 0;

    // version [0] EXPLICIT, present for v3 and absent for v1.
    if fields.first().map(|f| f.tag) == Some(0xA0) {
        at = 1;
    }

    let serial = fields
        .get(at)
        .filter(|f| f.tag == TAG_INTEGER)
        .map(|f| {
            f.value
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
        .unwrap_or_default();
    at += 1;
    at += 1; // signature AlgorithmIdentifier

    let issuer = fields
        .get(at)
        .ok_or_else(|| DerError("missing issuer".into()))?;
    let (issuer_name, issuer_cn, _) = parse_name(issuer.value)?;
    at += 1;

    let validity = fields
        .get(at)
        .ok_or_else(|| DerError("missing validity".into()))?;
    let times = children(validity.value)?;
    let not_before = times.first().map(decode_time).unwrap_or_default();
    let not_after = times.get(1).map(decode_time).unwrap_or_default();
    at += 1;

    let subject = fields
        .get(at)
        .ok_or_else(|| DerError("missing subject".into()))?;
    let (subject_name, subject_cn, subject_org) = parse_name(subject.value)?;
    at += 1;

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    let spki = fields
        .get(at)
        .ok_or_else(|| DerError("missing subjectPublicKeyInfo".into()))?;
    let spki_parts = children(spki.value)?;
    let algorithm = spki_parts
        .first()
        .and_then(|a| children(a.value).ok())
        .and_then(|a| a.first().map(|oid| oid_to_string(oid.value)))
        .unwrap_or_default();
    let key_bits = spki_parts
        .get(1)
        .filter(|k| k.tag == TAG_BIT_STRING)
        .ok_or_else(|| DerError("public key is not a BIT STRING".into()))?;
    // A BIT STRING leads with a count of unused trailing bits, always zero for
    // a key, and the key itself follows.
    let public_key = key_bits.value.get(1..).unwrap_or_default().to_vec();
    at += 1;

    // Optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
    let mut extended_key_usage = Vec::new();
    let mut is_ca = false;
    for field in fields.iter().skip(at) {
        if field.tag != 0xA3 {
            continue;
        }
        let Some(sequence) = children(field.value)?.into_iter().next() else {
            continue;
        };
        for extension in children(sequence.value)? {
            let parts = children(extension.value)?;
            let Some(oid) = parts.first().filter(|o| o.tag == TAG_OID) else {
                continue;
            };
            let oid = oid_to_string(oid.value);
            // `critical` is optional and defaults to false, so the OCTET STRING
            // is whichever of the remaining elements has that tag.
            let Some(payload) = parts.iter().find(|p| p.tag == TAG_OCTET_STRING) else {
                continue;
            };

            match oid.as_str() {
                OID_EXTENDED_KEY_USAGE => {
                    if let Ok(sequence) = read_tlv(payload.value) {
                        for oid in children(sequence.value)? {
                            if oid.tag == TAG_OID {
                                extended_key_usage
                                    .push(eku_name(&oid_to_string(oid.value)).to_string());
                            }
                        }
                    }
                }
                OID_BASIC_CONSTRAINTS => {
                    if let Ok(sequence) = read_tlv(payload.value) {
                        is_ca = children(sequence.value)?
                            .iter()
                            .any(|c| c.tag == TAG_BOOLEAN && c.value.first() == Some(&0xFF));
                    }
                }
                _ => {}
            }
        }
    }

    Ok(Certificate {
        subject: subject_name,
        subject_common_name: subject_cn,
        subject_organisation: subject_org,
        issuer: issuer_name,
        issuer_common_name: issuer_cn,
        not_before,
        not_after,
        serial,
        public_key,
        public_key_algorithm: algorithm,
        extended_key_usage,
        is_ca,
    })
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

    /// The demo signer, compiled in by build.rs. Parsing the real certificate
    /// beats a hand-built fixture: it is what actually ships.
    fn demo_certificate() -> Certificate {
        let der = pem_to_der(crate::c2pa::signer::SIGNING_CERT_CHAIN_PEM).unwrap();
        parse_certificate(&der[0]).unwrap()
    }

    #[test]
    fn reads_the_shipped_signing_certificate() {
        let cert = demo_certificate();
        assert!(
            cert.subject_common_name.contains("Signer"),
            "unexpected subject {:?}",
            cert.subject
        );
        assert!(!cert.issuer.is_empty());
        assert_ne!(
            cert.issuer, cert.subject,
            "the leaf must not be self-signed"
        );
        assert!(!cert.serial.is_empty());
    }

    #[test]
    fn extracts_a_usable_p256_public_key() {
        let cert = demo_certificate();
        // Uncompressed SEC1 point: 0x04 then two 32-byte coordinates.
        assert_eq!(cert.public_key.len(), 65);
        assert_eq!(cert.public_key[0], 0x04);
        assert_eq!(cert.public_key_algorithm, "1.2.840.10045.2.1"); // id-ecPublicKey
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&cert.public_key)
            .expect("the parsed key should load");
    }

    #[test]
    fn the_signer_matches_the_c2pa_certificate_profile() {
        // Section 14.5.1: an end-entity certificate needs a non-empty EKU, must
        // not claim anyExtendedKeyUsage, and must not be a CA.
        let cert = demo_certificate();
        assert!(!cert.is_ca, "a CA certificate may not sign claims");
        assert!(!cert.extended_key_usage.is_empty(), "EKU is required");
        assert!(!cert
            .extended_key_usage
            .iter()
            .any(|eku| eku == "anyExtendedKeyUsage"));
        assert!(
            cert.extended_key_usage
                .iter()
                .any(|eku| eku == "emailProtection" || eku == "documentSigning"),
            "expected a C2PA claim-signing EKU, got {:?}",
            cert.extended_key_usage
        );
    }

    #[test]
    fn reads_validity_dates_as_iso_8601() {
        let cert = demo_certificate();
        assert!(
            cert.not_before.len() == 20 && cert.not_before.ends_with('Z'),
            "unexpected notBefore {:?}",
            cert.not_before
        );
        assert!(cert.not_after > cert.not_before);
    }

    #[test]
    fn recognises_the_root_as_a_ca() {
        let der = pem_to_der(crate::c2pa::signer::SIGNING_ROOT_CA_PEM).unwrap();
        let root = parse_certificate(&der[0]).unwrap();
        assert!(root.is_ca);
        assert_eq!(root.issuer, root.subject, "the root should be self-signed");
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
