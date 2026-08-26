//! A small DER writer.
//!
//! The parser in [`super::x509`] reads certificates; this writes the handful of
//! ASN.1 structures the product has to *produce*: an RFC 3161 `TimeStampReq`
//! for the Backend to send to a time-stamping authority, and — in tests — the
//! `TimeStampToken` a stand-in authority answers with, so the whole time-stamp
//! path is exercised against real DER rather than a mock.
//!
//! Definite-length, minimal-length encodings throughout, which is what DER
//! means and what every verifier re-deriving a digest over these bytes assumes.

/// Encode a tag, length and value.
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        // Minimal long form: only the bytes the length actually needs.
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(value);
    out
}

fn concat(items: &[Vec<u8>]) -> Vec<u8> {
    items.iter().flat_map(|i| i.iter().copied()).collect()
}

pub fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &concat(items))
}

pub fn set_of(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &concat(items))
}

pub fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(0x04, value)
}

pub fn boolean(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xFF } else { 0x00 }])
}

pub fn null() -> Vec<u8> {
    tlv(0x05, &[])
}

/// A context-specific constructed wrapper, `[n] EXPLICIT`.
pub fn explicit(number: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xA0 | number, inner)
}

/// A context-specific primitive, `[n] IMPLICIT`, keeping the inner content.
pub fn implicit_primitive(number: u8, value: &[u8]) -> Vec<u8> {
    tlv(0x80 | number, value)
}

/// A context-specific constructed value with the tag replaced, `[n] IMPLICIT`
/// over a constructed type.
pub fn implicit_constructed(number: u8, encoded: &[u8]) -> Vec<u8> {
    let mut out = encoded.to_vec();
    if let Some(first) = out.first_mut() {
        *first = 0xA0 | number;
    }
    out
}

/// A non-negative INTEGER.
pub fn integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut body = bytes[first..].to_vec();
    // DER integers are signed, so a leading zero keeps a high bit from reading
    // as a negative number.
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(0x02, &body)
}

/// An OBJECT IDENTIFIER from its dotted-decimal form.
pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').filter_map(|a| a.parse().ok()).collect();
    let mut body = Vec::new();
    if arcs.len() >= 2 {
        body.push((arcs[0] * 40 + arcs[1]) as u8);
        for arc in &arcs[2..] {
            let mut stack = Vec::new();
            let mut value = *arc;
            loop {
                stack.push((value & 0x7F) as u8);
                value >>= 7;
                if value == 0 {
                    break;
                }
            }
            for (index, byte) in stack.iter().rev().enumerate() {
                body.push(if index + 1 == stack.len() {
                    *byte
                } else {
                    byte | 0x80
                });
            }
        }
    }
    tlv(0x06, &body)
}

/// A `GeneralizedTime` in the `YYYYMMDDHHMMSSZ` form DER requires.
pub fn generalized_time(at: super::clock::Instant) -> Vec<u8> {
    let text = super::clock::to_rfc3339(at)
        .replace(['-', ':'], "")
        .replace('T', "");
    tlv(0x18, text.as_bytes())
}

/// An `AlgorithmIdentifier` with absent parameters, as the elliptic-curve
/// signature algorithms use.
pub fn algorithm(oid_text: &str) -> Vec<u8> {
    sequence(&[oid(oid_text)])
}

/// An `AlgorithmIdentifier` with explicit NULL parameters, as the SHA-2 digest
/// algorithms conventionally carry.
pub fn algorithm_with_null(oid_text: &str) -> Vec<u8> {
    sequence(&[oid(oid_text), null()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::x509;

    #[test]
    fn short_and_long_lengths_round_trip_through_the_parser() {
        for size in [0usize, 1, 127, 128, 255, 256, 4096] {
            let encoded = octet_string(&vec![0xAB; size]);
            let parsed = x509::read_tlv(&encoded).unwrap();
            assert_eq!(parsed.tag, 0x04);
            assert_eq!(parsed.value.len(), size, "size {size}");
            assert_eq!(parsed.total, encoded.len(), "size {size}");
        }
    }

    #[test]
    fn oids_round_trip() {
        for dotted in [
            "1.2.840.113549.1.7.2",
            "2.16.840.1.101.3.4.2.1",
            "1.3.6.1.4.1.62558.3.10",
            "1.3.101.112",
        ] {
            let encoded = oid(dotted);
            let parsed = x509::read_tlv(&encoded).unwrap();
            assert_eq!(x509::oid_to_string(parsed.value), dotted);
        }
    }

    #[test]
    fn integers_keep_their_sign_guard() {
        // 0x80 must not encode as a negative number.
        assert_eq!(integer(0x80), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(integer(0), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn generalized_time_round_trips_through_the_parser() {
        let at = crate::c2pa::clock::parse_rfc3339("2026-08-26T12:34:56Z").unwrap();
        let encoded = generalized_time(at);
        let parsed = x509::read_tlv(&encoded).unwrap();
        assert_eq!(x509::decode_time_instant(&parsed), Some(at));
    }

    #[test]
    fn implicit_tagging_rewrites_the_tag_without_disturbing_the_body() {
        let inner = sequence(&[integer(1)]);
        let tagged = implicit_constructed(0, &inner);
        assert_eq!(tagged[0], 0xA0);
        assert_eq!(&tagged[1..], &inner[1..]);
    }
}
