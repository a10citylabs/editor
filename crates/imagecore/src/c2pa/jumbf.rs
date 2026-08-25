//! JUMBF boxes (ISO/IEC 19566-5), the container C2PA manifests live in.
//!
//! The format is small. Every box is a four-byte big-endian length covering
//! itself, a four-byte type, then payload:
//!
//! ```text
//!   +--------+--------+---------------------------+
//!   |  LBox  |  TBox  |          payload          |
//!   | 4 bytes| 4 bytes|                           |
//!   +--------+--------+---------------------------+
//! ```
//!
//! A *superbox* has type `jumb`, and its payload is a description box (`jumd`)
//! followed by any number of child boxes. The description box carries a 16-byte
//! type UUID saying what the superbox holds, a byte of toggles, and — when the
//! toggles say so — a NUL-terminated label. C2PA addresses everything by those
//! labels, which is why every box this module writes is both requestable and
//! labelled (toggles `0x03`).
//!
//! ```text
//!   c2pa                                  (manifest store)
//!   └── urn:c2pa:<uuid>                   (manifest, c2ma)
//!       ├── c2pa.assertions               (assertion store, c2as)
//!       │   ├── c2pa.actions.v2           (cbor)
//!       │   ├── c2pa.ingredient.v3        (cbor)
//!       │   ├── c2pa.thumbnail.claim      (bfdb + bidb)
//!       │   └── c2pa.hash.data            (cbor)
//!       ├── c2pa.claim.v2                 (cbor)
//!       └── c2pa.signature                (cbor: COSE_Sign1)
//! ```
//!
//! The one subtlety worth stating up front is how boxes get hashed. Section
//! 8.4.2.3 of the C2PA specification says a hashed URI covers "the contents of
//! the structure's JUMBF superbox, which includes both the JUMBF Description
//! Box and all content boxes therein (but does not include the structure's
//! JUMBF superbox header)". That is [`Superbox::contents_for_hash`]: everything
//! except the outer eight bytes. Hashing the wrong span is the single easiest
//! way to produce a manifest that looks perfect and validates nowhere, so it
//! has its own function rather than an offset at the call site.

use std::fmt;

/// A superbox: `LBox`, `TBox` = `jumb`, then a description box and children.
pub const TBOX_SUPERBOX: [u8; 4] = *b"jumb";
/// A description box: the type UUID, toggles and label of its parent superbox.
pub const TBOX_DESCRIPTION: [u8; 4] = *b"jumd";
/// A content box holding CBOR.
pub const TBOX_CBOR: [u8; 4] = *b"cbor";
/// A content box holding JSON.
pub const TBOX_JSON: [u8; 4] = *b"json";
/// The description half of an embedded file (its media type).
pub const TBOX_EMBEDDED_FILE_DESCRIPTION: [u8; 4] = *b"bfdb";
/// The data half of an embedded file.
pub const TBOX_EMBEDDED_FILE_DATA: [u8; 4] = *b"bidb";

/// Content-type UUIDs from C2PA 2.2, section 11.1.4. Each is a four-character
/// tag padded into the JUMBF UUID shape `xxxxxxxx-0011-0010-8000-00AA00389B71`.
macro_rules! jumbf_uuid {
    ($tag:expr) => {{
        let tag = $tag;
        [
            tag[0], tag[1], tag[2], tag[3], 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00,
            0x38, 0x9B, 0x71,
        ]
    }};
}

/// `c2pa` — the manifest store at the root.
pub const UUID_MANIFEST_STORE: [u8; 16] = jumbf_uuid!(*b"c2pa");
/// `c2ma` — a standard manifest.
pub const UUID_MANIFEST: [u8; 16] = jumbf_uuid!(*b"c2ma");
/// `c2um` — an update manifest.
pub const UUID_UPDATE_MANIFEST: [u8; 16] = jumbf_uuid!(*b"c2um");
/// `c2as` — the assertion store.
pub const UUID_ASSERTION_STORE: [u8; 16] = jumbf_uuid!(*b"c2as");
/// `c2cl` — the claim.
pub const UUID_CLAIM: [u8; 16] = jumbf_uuid!(*b"c2cl");
/// `c2cs` — the claim signature.
pub const UUID_SIGNATURE: [u8; 16] = jumbf_uuid!(*b"c2cs");

/// The UUID JUMBF assigns to a CBOR content type, used on assertion superboxes
/// whose payload is a single `cbor` box.
pub const UUID_CBOR: [u8; 16] = [
    0x63, 0x62, 0x6F, 0x72, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];
/// The UUID JUMBF assigns to an embedded file, used on thumbnail assertions.
pub const UUID_EMBEDDED_FILE: [u8; 16] = [
    0x40, 0xCB, 0x0C, 0x32, 0xBB, 0x8A, 0x48, 0x9D, 0xA7, 0x0B, 0x2A, 0xD6, 0xF4, 0x7F, 0x43, 0x69,
];

/// Requestable (bit 0) + label present (bit 1). Every C2PA box is addressed by
/// label, so nothing this module writes uses any other combination.
const TOGGLE_REQUESTABLE_LABELLED: u8 = 0x03;
const TOGGLE_LABEL_PRESENT: u8 = 0x02;
const TOGGLE_ID_PRESENT: u8 = 0x04;
const TOGGLE_SIGNATURE_PRESENT: u8 = 0x08;
const TOGGLE_PRIVATE_PRESENT: u8 = 0x10;

/// `LBox` + `TBox`.
pub const BOX_HEADER_LEN: usize = 8;

#[derive(Debug)]
pub struct JumbfError(String);

impl fmt::Display for JumbfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed JUMBF: {}", self.0)
    }
}

impl std::error::Error for JumbfError {}

type Result<T> = std::result::Result<T, JumbfError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(JumbfError(message.into()))
}

/// A child of a superbox: either a nested superbox or a leaf content box.
#[derive(Clone, Debug)]
pub enum Child {
    Super(Superbox),
    Content(ContentBox),
}

#[derive(Clone, Debug)]
pub struct ContentBox {
    pub tbox: [u8; 4],
    pub data: Vec<u8>,
}

impl ContentBox {
    pub fn new(tbox: [u8; 4], data: impl Into<Vec<u8>>) -> Self {
        ContentBox {
            tbox,
            data: data.into(),
        }
    }

    pub fn cbor(data: impl Into<Vec<u8>>) -> Self {
        ContentBox::new(TBOX_CBOR, data)
    }

    fn len(&self) -> usize {
        BOX_HEADER_LEN + self.data.len()
    }

    fn write(&self, out: &mut Vec<u8>) {
        write_header(out, self.len(), self.tbox);
        out.extend_from_slice(&self.data);
    }
}

/// A labelled JUMBF superbox.
#[derive(Clone, Debug)]
pub struct Superbox {
    pub uuid: [u8; 16],
    pub label: String,
    pub children: Vec<Child>,
    /// Bytes of any private field in the description box, kept verbatim so a
    /// box that was read back hashes to the same value it did on the way in.
    /// This crate never writes one; C2PA uses it for the optional `c2sh` salt.
    private: Vec<u8>,
    /// Toggles exactly as read, so a parsed box re-serialises byte-identically.
    toggles: u8,
    box_id: Option<u32>,
    signature: Option<[u8; 32]>,
}

impl Superbox {
    pub fn new(uuid: [u8; 16], label: impl Into<String>) -> Self {
        Superbox {
            uuid,
            label: label.into(),
            children: Vec::new(),
            private: Vec::new(),
            toggles: TOGGLE_REQUESTABLE_LABELLED,
            box_id: None,
            signature: None,
        }
    }

    pub fn with_child(mut self, child: Child) -> Self {
        self.children.push(child);
        self
    }

    /// A superbox holding one CBOR content box, which is the shape of almost
    /// every C2PA assertion.
    pub fn cbor(uuid: [u8; 16], label: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Superbox::new(uuid, label).with_child(Child::Content(ContentBox::cbor(data)))
    }

    pub fn push(&mut self, child: Child) {
        self.children.push(child);
    }

    /// Serialised size, header included.
    pub fn encoded_len(&self) -> usize {
        BOX_HEADER_LEN + self.description_len() + self.children_len()
    }

    fn children_len(&self) -> usize {
        self.children
            .iter()
            .map(|child| match child {
                Child::Super(b) => b.encoded_len(),
                Child::Content(b) => b.len(),
            })
            .sum()
    }

    fn description_len(&self) -> usize {
        let mut len = BOX_HEADER_LEN + 16 + 1;
        if self.toggles & TOGGLE_LABEL_PRESENT != 0 {
            len += self.label.len() + 1; // NUL terminator
        }
        if self.box_id.is_some() {
            len += 4;
        }
        if self.signature.is_some() {
            len += 32;
        }
        len += self.private.len();
        len
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        write_header(out, self.encoded_len(), TBOX_SUPERBOX);
        self.write_description(out);
        for child in &self.children {
            match child {
                Child::Super(b) => b.write(out),
                Child::Content(b) => b.write(out),
            }
        }
    }

    fn write_description(&self, out: &mut Vec<u8>) {
        write_header(out, self.description_len(), TBOX_DESCRIPTION);
        out.extend_from_slice(&self.uuid);
        out.push(self.toggles);
        if self.toggles & TOGGLE_LABEL_PRESENT != 0 {
            out.extend_from_slice(self.label.as_bytes());
            out.push(0);
        }
        if let Some(id) = self.box_id {
            out.extend_from_slice(&id.to_be_bytes());
        }
        if let Some(signature) = self.signature {
            out.extend_from_slice(&signature);
        }
        out.extend_from_slice(&self.private);
    }

    /// The bytes a hashed URI covers: the description box and all content
    /// boxes, but not this superbox's own `LBox`/`TBox`.
    ///
    /// C2PA 2.2, section 8.4.2.3.
    pub fn contents_for_hash(&self) -> Vec<u8> {
        let mut out = self.to_bytes();
        out.drain(..BOX_HEADER_LEN);
        out
    }

    /// The single CBOR payload of this box, if it has one.
    pub fn cbor_payload(&self) -> Option<&[u8]> {
        self.children.iter().find_map(|child| match child {
            Child::Content(b) if b.tbox == TBOX_CBOR => Some(b.data.as_slice()),
            _ => None,
        })
    }

    /// The bytes and media type of an embedded file payload (`bfdb` + `bidb`).
    pub fn embedded_file(&self) -> Option<(String, &[u8])> {
        let mut media_type = String::new();
        let mut data = None;
        for child in &self.children {
            match child {
                Child::Content(b) if b.tbox == TBOX_EMBEDDED_FILE_DESCRIPTION => {
                    // One byte of toggles, then a NUL-terminated media type.
                    let rest = b.data.get(1..).unwrap_or_default();
                    let end = rest.iter().position(|c| *c == 0).unwrap_or(rest.len());
                    media_type = String::from_utf8_lossy(&rest[..end]).into_owned();
                }
                Child::Content(b) if b.tbox == TBOX_EMBEDDED_FILE_DATA => {
                    data = Some(b.data.as_slice());
                }
                _ => {}
            }
        }
        data.map(|d| (media_type, d))
    }

    /// Direct child superbox with this label.
    pub fn child(&self, label: &str) -> Option<&Superbox> {
        self.children.iter().find_map(|child| match child {
            Child::Super(b) if b.label == label => Some(b),
            _ => None,
        })
    }

    /// Every direct child superbox, in order.
    pub fn child_boxes(&self) -> impl Iterator<Item = &Superbox> {
        self.children.iter().filter_map(|child| match child {
            Child::Super(b) => Some(b),
            _ => None,
        })
    }

    /// Resolve a slash-separated label path, e.g. `c2pa.assertions/c2pa.actions.v2`.
    ///
    /// A label that appears more than once at the same level makes the path
    /// ambiguous, and section 8.4.1 says a validator shall then treat the
    /// reference as unresolved. Returning `None` is that.
    pub fn resolve(&self, path: &str) -> Option<&Superbox> {
        let mut current = self;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            let mut matches = current.child_boxes().filter(|b| b.label == segment);
            let found = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            current = found;
        }
        Some(current)
    }
}

/// Build an embedded-file superbox: a `bfdb` media-type box plus a `bidb` data
/// box. This is how C2PA carries thumbnails (section 18.11).
pub fn embedded_file_box(
    label: impl Into<String>,
    media_type: &str,
    data: impl Into<Vec<u8>>,
) -> Superbox {
    let mut description = Vec::with_capacity(media_type.len() + 2);
    description.push(0x00); // toggles: the payload is data, not a file name
    description.extend_from_slice(media_type.as_bytes());
    description.push(0);

    Superbox::new(UUID_EMBEDDED_FILE, label)
        .with_child(Child::Content(ContentBox::new(
            TBOX_EMBEDDED_FILE_DESCRIPTION,
            description,
        )))
        .with_child(Child::Content(ContentBox::new(
            TBOX_EMBEDDED_FILE_DATA,
            data,
        )))
}

fn write_header(out: &mut Vec<u8>, len: usize, tbox: [u8; 4]) {
    // Every box this crate writes is far below 4GB, so the 64-bit XLBox form
    // never comes up. Saturating rather than wrapping means a hypothetical
    // overflow produces an obviously broken length instead of a tiny one that
    // a reader would follow into the middle of a box.
    out.extend_from_slice(&(u32::try_from(len).unwrap_or(u32::MAX)).to_be_bytes());
    out.extend_from_slice(&tbox);
}

/* ------------------------------------------------------------------------- */
/* Parsing                                                                    */
/* ------------------------------------------------------------------------- */

/// Nesting limit for untrusted input, mirroring the CBOR reader's.
const MAX_DEPTH: usize = 32;

/// Parse one superbox from the front of `bytes`, rejecting trailing data.
pub fn parse(bytes: &[u8]) -> Result<Superbox> {
    let (superbox, consumed) = parse_superbox(bytes, 0)?;
    if consumed != bytes.len() {
        return err(format!(
            "{} bytes follow the superbox",
            bytes.len() - consumed
        ));
    }
    Ok(superbox)
}

fn read_header(bytes: &[u8]) -> Result<(usize, [u8; 4])> {
    if bytes.len() < BOX_HEADER_LEN {
        return err("box header truncated");
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let tbox = [bytes[4], bytes[5], bytes[6], bytes[7]];

    // LBox == 0 means "to the end of the file" and LBox == 1 means a 64-bit
    // XLBox follows. Neither appears in a C2PA manifest store, and accepting
    // them would mean carrying two more length paths through the parser.
    if len < BOX_HEADER_LEN {
        return err(format!("box length {len} is smaller than its header"));
    }
    if len > bytes.len() {
        return err(format!(
            "box claims {len} bytes but only {} are present",
            bytes.len()
        ));
    }
    Ok((len, tbox))
}

fn parse_superbox(bytes: &[u8], depth: usize) -> Result<(Superbox, usize)> {
    if depth > MAX_DEPTH {
        return err("superboxes nested deeper than 32 levels");
    }

    let (len, tbox) = read_header(bytes)?;
    if tbox != TBOX_SUPERBOX {
        return err(format!(
            "expected a 'jumb' superbox, found '{}'",
            String::from_utf8_lossy(&tbox)
        ));
    }

    let body = &bytes[BOX_HEADER_LEN..len];
    let (description, description_len) = parse_description(body)?;
    let mut at = description_len;
    let mut children = Vec::new();

    while at < body.len() {
        let (child_len, child_tbox) = read_header(&body[at..])?;
        if child_tbox == TBOX_SUPERBOX {
            let (child, consumed) = parse_superbox(&body[at..], depth + 1)?;
            children.push(Child::Super(child));
            at += consumed;
        } else {
            children.push(Child::Content(ContentBox {
                tbox: child_tbox,
                data: body[at + BOX_HEADER_LEN..at + child_len].to_vec(),
            }));
            at += child_len;
        }
    }

    Ok((
        Superbox {
            children,
            ..description
        },
        len,
    ))
}

/// Parse a `jumd` box into an empty superbox carrying its fields.
fn parse_description(bytes: &[u8]) -> Result<(Superbox, usize)> {
    let (len, tbox) = read_header(bytes)?;
    if tbox != TBOX_DESCRIPTION {
        return err(format!(
            "expected a 'jumd' description box, found '{}'",
            String::from_utf8_lossy(&tbox)
        ));
    }

    let body = &bytes[BOX_HEADER_LEN..len];
    if body.len() < 17 {
        return err("description box is too short for a UUID and toggles");
    }

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&body[..16]);
    let toggles = body[16];
    let mut at = 17;

    let label = if toggles & TOGGLE_LABEL_PRESENT != 0 {
        let rest = &body[at..];
        let end = rest
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| JumbfError("label is not NUL-terminated".into()))?;
        let label = std::str::from_utf8(&rest[..end])
            .map_err(|_| JumbfError("label is not valid UTF-8".into()))?
            .to_string();
        at += end + 1;
        label
    } else {
        String::new()
    };

    let box_id = if toggles & TOGGLE_ID_PRESENT != 0 {
        if body.len() < at + 4 {
            return err("description box is too short for its box id");
        }
        let id = u32::from_be_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
        at += 4;
        Some(id)
    } else {
        None
    };

    let signature = if toggles & TOGGLE_SIGNATURE_PRESENT != 0 {
        if body.len() < at + 32 {
            return err("description box is too short for its signature");
        }
        let mut sig = [0u8; 32];
        sig.copy_from_slice(&body[at..at + 32]);
        at += 32;
        Some(sig)
    } else {
        None
    };

    // Anything left is the private field - in C2PA, the optional `c2sh` salt.
    // It is kept verbatim rather than parsed: it contributes to the box's hash,
    // so losing it would break validation of a file this crate did not write.
    let private = if toggles & TOGGLE_PRIVATE_PRESENT != 0 {
        body[at..].to_vec()
    } else {
        Vec::new()
    };

    Ok((
        Superbox {
            uuid,
            label,
            children: Vec::new(),
            private,
            toggles,
            box_id,
            signature,
        },
        len,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_match_the_specification() {
        // C2PA 2.2 section 11.1.4 spells these out in full; the macro has to
        // reproduce them exactly or nothing downstream recognises the store.
        assert_eq!(
            UUID_MANIFEST_STORE,
            [
                0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38,
                0x9B, 0x71
            ]
        );
        assert_eq!(&UUID_MANIFEST[..4], b"c2ma");
        assert_eq!(&UUID_ASSERTION_STORE[..4], b"c2as");
        assert_eq!(&UUID_CLAIM[..4], b"c2cl");
        assert_eq!(&UUID_SIGNATURE[..4], b"c2cs");
        assert_eq!(&UUID_UPDATE_MANIFEST[..4], b"c2um");
    }

    #[test]
    fn round_trips_a_nested_store() {
        let assertions = Superbox::new(UUID_ASSERTION_STORE, "c2pa.assertions")
            .with_child(Child::Super(Superbox::cbor(
                UUID_CBOR,
                "c2pa.actions.v2",
                vec![0xA0],
            )))
            .with_child(Child::Super(Superbox::cbor(
                UUID_CBOR,
                "c2pa.hash.data",
                vec![0xA1, 0x01, 0x02],
            )));

        let manifest = Superbox::new(UUID_MANIFEST, "urn:c2pa:test")
            .with_child(Child::Super(assertions))
            .with_child(Child::Super(Superbox::cbor(
                UUID_CLAIM,
                "c2pa.claim.v2",
                vec![0xA0],
            )));

        let store = Superbox::new(UUID_MANIFEST_STORE, "c2pa").with_child(Child::Super(manifest));
        let bytes = store.to_bytes();

        assert_eq!(bytes.len(), store.encoded_len());
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.label, "c2pa");
        assert_eq!(parsed.uuid, UUID_MANIFEST_STORE);
        assert_eq!(parsed.to_bytes(), bytes);

        let actions = parsed
            .resolve("urn:c2pa:test/c2pa.assertions/c2pa.actions.v2")
            .expect("resolvable path");
        assert_eq!(actions.cbor_payload(), Some(&[0xA0][..]));
    }

    #[test]
    fn header_length_covers_the_header_itself() {
        let leaf = Superbox::cbor(UUID_CBOR, "x", vec![1, 2, 3, 4]);
        let bytes = leaf.to_bytes();
        let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(declared, bytes.len());
        assert_eq!(&bytes[4..8], b"jumb");
    }

    #[test]
    fn hashed_contents_skip_only_the_outer_header() {
        let leaf = Superbox::cbor(UUID_CBOR, "c2pa.actions.v2", vec![0xA0]);
        let full = leaf.to_bytes();
        let hashed = leaf.contents_for_hash();

        assert_eq!(hashed.len(), full.len() - BOX_HEADER_LEN);
        assert_eq!(hashed, full[BOX_HEADER_LEN..]);
        // The description box must be inside the hash: it carries the label,
        // so leaving it out would let an assertion be relabelled undetected.
        assert_eq!(&hashed[4..8], b"jumd");
    }

    #[test]
    fn embedded_files_round_trip() {
        let thumb = embedded_file_box("c2pa.thumbnail.claim", "image/jpeg", vec![0xFF, 0xD8, 0xFF]);
        let parsed = parse(&thumb.to_bytes()).unwrap();
        let (media_type, data) = parsed.embedded_file().expect("embedded file");
        assert_eq!(media_type, "image/jpeg");
        assert_eq!(data, &[0xFF, 0xD8, 0xFF]);
    }

    #[test]
    fn ambiguous_labels_do_not_resolve() {
        // Section 8.4.1: a duplicated label makes the reference unresolvable.
        let store = Superbox::new(UUID_ASSERTION_STORE, "c2pa.assertions")
            .with_child(Child::Super(Superbox::cbor(UUID_CBOR, "dup", vec![0xA0])))
            .with_child(Child::Super(Superbox::cbor(UUID_CBOR, "dup", vec![0xA0])));
        assert!(store.resolve("dup").is_none());
        assert!(store.resolve("missing").is_none());
    }

    #[test]
    fn a_parsed_box_with_a_salt_re_serialises_byte_for_byte() {
        // This crate writes no salt, but a file from another generator may have
        // one, and its bytes are part of that assertion's hash.
        let mut description = Vec::new();
        description.extend_from_slice(&UUID_CBOR);
        description.push(0x13); // requestable + label + private
        description.extend_from_slice(b"c2pa.actions.v2\0");
        let salt = {
            let mut b = Vec::new();
            b.extend_from_slice(&24u32.to_be_bytes());
            b.extend_from_slice(b"c2sh");
            b.extend_from_slice(&[7u8; 16]);
            b
        };
        description.extend_from_slice(&salt);

        let mut jumd = Vec::new();
        jumd.extend_from_slice(&((description.len() + 8) as u32).to_be_bytes());
        jumd.extend_from_slice(b"jumd");
        jumd.extend_from_slice(&description);

        let mut cbor_box = Vec::new();
        cbor_box.extend_from_slice(&9u32.to_be_bytes());
        cbor_box.extend_from_slice(b"cbor");
        cbor_box.push(0xA0);

        let mut superbox = Vec::new();
        superbox.extend_from_slice(&((jumd.len() + cbor_box.len() + 8) as u32).to_be_bytes());
        superbox.extend_from_slice(b"jumb");
        superbox.extend_from_slice(&jumd);
        superbox.extend_from_slice(&cbor_box);

        let parsed = parse(&superbox).unwrap();
        assert_eq!(parsed.label, "c2pa.actions.v2");
        assert_eq!(
            parsed.to_bytes(),
            superbox,
            "a salted description box must survive a parse/serialise round trip"
        );
    }

    #[test]
    fn rejects_lengths_that_run_past_the_input() {
        let mut bytes = Superbox::cbor(UUID_CBOR, "x", vec![1]).to_bytes();
        bytes[3] = 0xFF; // inflate LBox
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_a_zero_length_box() {
        // LBox 0 means "runs to end of file" in JUMBF; following it blindly is
        // how a parser ends up in an infinite loop.
        let bytes = vec![0, 0, 0, 0, b'j', b'u', b'm', b'b'];
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = Superbox::cbor(UUID_CBOR, "x", vec![1]).to_bytes();
        bytes.push(0);
        assert!(parse(&bytes).is_err());
    }
}
