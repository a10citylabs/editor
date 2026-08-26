//! Just enough CBOR (RFC 8949) to write and read C2PA structures.
//!
//! C2PA requires claims to use the *Core Deterministic Encoding Requirements*
//! of RFC 8949, clause 4.2.1: shortest-form integers and lengths, definite
//! lengths only, and map keys sorted by the bytewise lexicographic order of
//! their own encodings. [`Value::encode`] does all three unconditionally, so
//! there is no way to accidentally emit a non-deterministic claim.
//!
//! The one deliberate exception is [`Value::Uint32`], which always writes its
//! argument in the four-byte form even when a shorter one exists. Section
//! 18.5.2 of the specification asks for exactly that: a data hash assertion has
//! to be built before the byte offsets it describes are known, so its `start`
//! and `length` are written "as large as possible, which would be as a 32-bit
//! integer" and patched afterwards without the structure changing size. Keeping
//! the width fixed is what lets this crate build a manifest, measure it, and
//! then fill in the real offsets in a single rebuild.
//!
//! A general-purpose crate would carry a lot more than this: floats, indefinite
//! lengths, streaming. None of it appears in the parts of C2PA this engine
//! touches, and leaving it out keeps the WebAssembly module small.

use std::collections::BTreeMap;
use std::fmt;

/// Major types, in the high three bits of the initial byte.
const MT_UINT: u8 = 0;
const MT_NEGINT: u8 = 1;
const MT_BYTES: u8 = 2;
const MT_TEXT: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
const MT_TAG: u8 = 6;
const MT_SIMPLE: u8 = 7;

/// CBOR tag 0: a standard date/time string (RFC 3339). C2PA's `when` fields
/// are `tdate`, which is this tag over a text string.
pub const TAG_DATETIME: u64 = 0;
/// CBOR tag 37: a binary UUID, used by `instanceID` inside action parameters.
pub const TAG_UUID: u64 = 37;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Uint(u64),
    /// A negative integer. Holds the value itself, e.g. `-7` for the COSE
    /// algorithm identifier ES256.
    NegInt(i64),
    /// A `uint` pinned to the four-byte encoding, for placeholder offsets that
    /// are patched once their real values are known. See the module docs.
    Uint32(u32),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn text(value: impl Into<String>) -> Self {
        Value::Text(value.into())
    }

    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Value::Bytes(value.into())
    }

    /// A tagged RFC 3339 timestamp, the `tdate` of the C2PA schemas.
    pub fn datetime(value: impl Into<String>) -> Self {
        Value::Tag(TAG_DATETIME, Box::new(Value::text(value)))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Value::Uint(n) => head(out, MT_UINT, *n),
            Value::NegInt(n) => {
                // CBOR stores -1-n, so -7 is encoded as the unsigned 6.
                let magnitude = (-1 - *n) as u64;
                head(out, MT_NEGINT, magnitude);
            }
            Value::Uint32(n) => {
                out.push((MT_UINT << 5) | 26);
                out.extend_from_slice(&n.to_be_bytes());
            }
            Value::Bytes(b) => {
                head(out, MT_BYTES, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                head(out, MT_TEXT, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                head(out, MT_ARRAY, items.len() as u64);
                for item in items {
                    item.write(out);
                }
            }
            Value::Map(entries) => {
                // Deterministic encoding orders keys by their encoded bytes,
                // not by their semantic value. Encoding the keys first and
                // sorting on the result is the definition, not an
                // approximation of it. A BTreeMap also collapses any duplicate
                // key, which a valid CBOR map cannot contain anyway.
                let mut sorted: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
                for (key, value) in entries {
                    sorted.insert(key.encode(), value.encode());
                }
                head(out, MT_MAP, sorted.len() as u64);
                for (key, value) in sorted {
                    out.extend_from_slice(&key);
                    out.extend_from_slice(&value);
                }
            }
            Value::Tag(tag, inner) => {
                head(out, MT_TAG, *tag);
                inner.write(out);
            }
            Value::Bool(b) => out.push((MT_SIMPLE << 5) | if *b { 21 } else { 20 }),
            // Major type 7, value 22. COSE uses this exclusively to mean
            // detached content; a zero-length byte string will not do
            // (C2PA 2.2, section 13.2.3).
            Value::Null => out.push((MT_SIMPLE << 5) | 22),
        }
    }

    /* ---- accessors used by the validator ---- */

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            // A tagged string still reads as that string; `when` fields arrive
            // wrapped in tag 0 and callers only ever want the text.
            Value::Tag(_, inner) => inner.as_text(),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            Value::Tag(_, inner) => inner.as_bytes(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(n) => Some(*n),
            Value::Uint32(n) => Some(u64::from(*n)),
            _ => None,
        }
    }

    /// Look a key up in a map by its text name.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }

    /// Look a key up in a map by an integer label, as COSE headers are keyed.
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        let wanted = if key < 0 {
            Value::NegInt(key)
        } else {
            Value::Uint(key as u64)
        };
        self.as_map()?
            .iter()
            .find(|(k, _)| match (k, &wanted) {
                (Value::Uint(a), Value::Uint(b)) => a == b,
                (Value::Uint32(a), Value::Uint(b)) => u64::from(*a) == *b,
                (Value::NegInt(a), Value::NegInt(b)) => a == b,
                _ => false,
            })
            .map(|(_, v)| v)
    }
}

fn head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let mt = major << 5;
    match argument {
        // Shortest form. This is what makes the encoding deterministic.
        0..=23 => out.push(mt | argument as u8),
        24..=0xFF => {
            out.push(mt | 24);
            out.push(argument as u8);
        }
        0x100..=0xFFFF => {
            out.push(mt | 25);
            out.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(mt | 26);
            out.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            out.push(mt | 27);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Decoding                                                                   */
/* ------------------------------------------------------------------------- */

#[derive(Debug)]
pub struct CborError(String);

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed CBOR: {}", self.0)
    }
}

impl std::error::Error for CborError {}

type Result<T> = std::result::Result<T, CborError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(CborError(message.into()))
}

/// Decode a single CBOR item, rejecting anything left over.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor { bytes, at: 0 };
    let value = cursor.item(0)?;
    if cursor.at != bytes.len() {
        return err(format!("{} trailing bytes", bytes.len() - cursor.at));
    }
    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

/// Bound on how deeply nested an item may be. A validator reads whatever a file
/// hands it, and without a limit a few dozen bytes of nested arrays would
/// recurse until the stack gave out.
const MAX_DEPTH: usize = 64;

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| CborError("input ended mid-item".into()))?;
        self.at += 1;
        Ok(b)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| CborError(format!("claimed length {count} runs past the end")))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    /// Read the initial byte's argument: the payload of the low five bits.
    fn argument(&mut self, initial: u8) -> Result<u64> {
        match initial & 0x1F {
            n @ 0..=23 => Ok(u64::from(n)),
            24 => Ok(u64::from(self.byte()?)),
            25 => {
                let b = self.take(2)?;
                Ok(u64::from(u16::from_be_bytes([b[0], b[1]])))
            }
            26 => {
                let b = self.take(4)?;
                Ok(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
            }
            27 => {
                let b = self.take(8)?;
                Ok(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            // 28..=30 are reserved; 31 marks an indefinite length, which C2PA's
            // deterministic encoding forbids.
            other => err(format!("unsupported additional information {other}")),
        }
    }

    /// A length that will be used to index into the input. Rejecting anything
    /// longer than the remaining input up front means a corrupt header cannot
    /// make us try to reserve gigabytes.
    fn length(&mut self, initial: u8) -> Result<usize> {
        let argument = self.argument(initial)?;
        let remaining = self.bytes.len() - self.at;
        if argument > remaining as u64 {
            return err(format!(
                "claimed length {argument} exceeds the {remaining} bytes left"
            ));
        }
        Ok(argument as usize)
    }

    fn item(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return err("nesting deeper than 64 levels");
        }

        let initial = self.byte()?;
        match initial >> 5 {
            MT_UINT => Ok(Value::Uint(self.argument(initial)?)),
            MT_NEGINT => {
                let magnitude = self.argument(initial)?;
                let value = i64::try_from(magnitude)
                    .map_err(|_| CborError("negative integer out of range".into()))?;
                Ok(Value::NegInt(-1 - value))
            }
            MT_BYTES => {
                let len = self.length(initial)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            MT_TEXT => {
                let len = self.length(initial)?;
                let raw = self.take(len)?;
                match std::str::from_utf8(raw) {
                    Ok(s) => Ok(Value::Text(s.to_string())),
                    Err(_) => err("text string is not valid UTF-8"),
                }
            }
            MT_ARRAY => {
                // Each element costs at least one byte, so a count larger than
                // the bytes remaining is a lie and we refuse to allocate for it.
                let count = self.length(initial)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            MT_MAP => {
                let count = self.length(initial)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let key = self.item(depth + 1)?;
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            MT_TAG => {
                let tag = self.argument(initial)?;
                Ok(Value::Tag(tag, Box::new(self.item(depth + 1)?)))
            }
            MT_SIMPLE => match initial & 0x1F {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                // `undefined`; nothing in C2PA writes it, but reading it as
                // null is friendlier than refusing the whole file.
                23 => Ok(Value::Null),
                other => err(format!("unsupported simple value {other}")),
            },
            _ => unreachable!("three bits cover 0..=7"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_use_the_shortest_form() {
        assert_eq!(Value::Uint(0).encode(), vec![0x00]);
        assert_eq!(Value::Uint(23).encode(), vec![0x17]);
        assert_eq!(Value::Uint(24).encode(), vec![0x18, 0x18]);
        assert_eq!(Value::Uint(1000).encode(), vec![0x19, 0x03, 0xE8]);
        assert_eq!(Value::NegInt(-7).encode(), vec![0x26]);
        assert_eq!(Value::NegInt(-1).encode(), vec![0x20]);
    }

    #[test]
    fn uint32_keeps_its_width_so_placeholders_can_be_patched() {
        // The whole two-pass manifest build rests on this: a value that grows
        // or shrinks when patched would move every byte after it.
        assert_eq!(Value::Uint32(0).encode().len(), 5);
        assert_eq!(Value::Uint32(u32::MAX).encode().len(), 5);
        assert_eq!(Value::Uint32(42).encode(), vec![0x1A, 0, 0, 0, 42]);
    }

    #[test]
    fn map_keys_are_sorted_by_their_encoding() {
        // RFC 8949 4.2.1 orders by encoded bytes, so the short key "z" sorts
        // before the longer "aa" - length is part of the encoding.
        let map = Value::Map(vec![
            (Value::text("aa"), Value::Uint(1)),
            (Value::text("z"), Value::Uint(2)),
            (Value::text("b"), Value::Uint(3)),
        ]);
        let encoded = map.encode();
        let decoded = decode(&encoded).unwrap();
        let keys: Vec<&str> = decoded
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.as_text().unwrap())
            .collect();
        assert_eq!(keys, vec!["b", "z", "aa"]);
    }

    #[test]
    fn encoding_is_stable_regardless_of_insertion_order() {
        let one = Value::Map(vec![
            (Value::text("alg"), Value::text("sha256")),
            (Value::text("hash"), Value::bytes(vec![1, 2, 3])),
        ]);
        let other = Value::Map(vec![
            (Value::text("hash"), Value::bytes(vec![1, 2, 3])),
            (Value::text("alg"), Value::text("sha256")),
        ]);
        assert_eq!(one.encode(), other.encode());
    }

    #[test]
    fn detached_payload_is_the_simple_value_22() {
        // COSE reserves this for detached content; an empty bstr is not a
        // legal substitute (C2PA 2.2 section 13.2.3).
        assert_eq!(Value::Null.encode(), vec![0xF6]);
        assert_ne!(Value::Null.encode(), Value::bytes(vec![]).encode());
    }

    #[test]
    fn round_trips_a_claim_shaped_structure() {
        let claim = Value::Map(vec![
            (Value::text("instanceID"), Value::text("xmp:iid:abc")),
            (
                Value::text("created_assertions"),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::text("url"),
                        Value::text("self#jumbf=c2pa.assertions/x"),
                    ),
                    (Value::text("hash"), Value::bytes(vec![9u8; 32])),
                ])]),
            ),
            (Value::text("when"), Value::datetime("2026-01-01T00:00:00Z")),
        ]);

        let decoded = decode(&claim.encode()).unwrap();
        assert_eq!(
            decoded.get("instanceID").unwrap().as_text(),
            Some("xmp:iid:abc")
        );
        assert_eq!(
            decoded.get("when").unwrap().as_text(),
            Some("2026-01-01T00:00:00Z")
        );
        let first = &decoded
            .get("created_assertions")
            .unwrap()
            .as_array()
            .unwrap()[0];
        assert_eq!(first.get("hash").unwrap().as_bytes().unwrap().len(), 32);
        // Re-encoding a decoded value reproduces the bytes exactly, which is
        // what lets the validator hash what it read.
        assert_eq!(decoded.encode(), claim.encode());
    }

    #[test]
    fn cose_headers_are_reachable_by_integer_label() {
        let protected = Value::Map(vec![
            (Value::Uint(1), Value::NegInt(-7)),
            (Value::Uint(33), Value::bytes(vec![0xAA])),
        ]);
        let decoded = decode(&protected.encode()).unwrap();
        assert_eq!(decoded.get_int(1), Some(&Value::NegInt(-7)));
        assert_eq!(decoded.get_int(33).unwrap().as_bytes(), Some(&[0xAA][..]));
        assert_eq!(decoded.get_int(4), None);
    }

    #[test]
    fn refuses_indefinite_lengths() {
        // 0x9F opens an indefinite-length array. Deterministic CBOR forbids it.
        assert!(decode(&[0x9F, 0x01, 0xFF]).is_err());
    }

    #[test]
    fn refuses_lengths_that_run_past_the_end() {
        // Claims a 16MB byte string in a 5-byte input.
        assert!(decode(&[0x5A, 0x01, 0x00, 0x00, 0x00]).is_err());
        // Claims 1000 array elements with none present.
        assert!(decode(&[0x99, 0x03, 0xE8]).is_err());
    }

    #[test]
    fn refuses_deep_nesting() {
        // 200 nested single-element arrays.
        let mut bytes = vec![0x81; 200];
        bytes.push(0x00);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn refuses_trailing_bytes() {
        assert!(decode(&[0x01, 0x02]).is_err());
    }
}
