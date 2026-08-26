//! Carrying a manifest store inside a JPEG, and finding one that is already
//! there.
//!
//! C2PA 2.2, section A.3.1 says the manifest store goes into `APP11` marker
//! segments "as defined in JPEG XT, ISO/IEC 18477-3". Each segment looks like:
//!
//! ```text
//!   FFEB   Le     'JP'    En      Z        LBox    TBox    payload
//!   marker 2 bytes 2 bytes 2 bytes 4 bytes  4 bytes 4 bytes ...
//!                  CI      box     packet   ... the JUMBF box header, repeated
//!                          instance sequence    in every segment
//! ```
//!
//! `Le` counts itself but not the marker, and cannot exceed 65535, so a
//! manifest larger than a segment is split across several. Two rules make the
//! reassembly unambiguous: the segments of one box share an `En` and number
//! their `Z` from 1, and `LBox`/`TBox` are repeated in *every* segment, "regardless
//! of whether the marker segment starts this box, or continues a box started by
//! a former" one. The first segment gets them for free because they are already
//! the first eight bytes of the JUMBF store; continuation segments carry a copy
//! that has to be stripped back off when reading.
//!
//! The other half of this module is the hard binding. A `c2pa.hash.data`
//! assertion hashes the file with the manifest's own bytes excluded — otherwise
//! the hash would have to cover itself. Section 18.5.3 is specific about where
//! that exclusion starts and stops: "the APP11 marker (`FFEB`) and the segment's
//! length (`Lp`) of all APP11 segments containing the JUMBF data shall be
//! included in the exclusion range". Excluding the markers and lengths too is
//! what stops an attacker from re-typing the excluded region into some other
//! segment that a decoder would act on.

use std::fmt;

const MARKER_PREFIX: u8 = 0xFF;
const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOS: u8 = 0xDA;
const APP0: u8 = 0xE0;
const APP11: u8 = 0xEB;

/// `CI` — the JPEG XT common identifier for a box-carrying segment.
const CI_JP: [u8; 2] = *b"JP";

/// `En`, the box instance number. Any value works so long as every segment of
/// one box shares it; this is the value `c2pa-rs` uses, so files from the two
/// implementations look alike byte for byte.
const BOX_INSTANCE: [u8; 2] = [0x02, 0x11];

/// `CI` + `En` + `Z`.
const XT_HEADER_LEN: usize = 2 + 2 + 4;
/// `LBox` + `TBox`, repeated in continuation segments.
const JUMBF_HEADER_LEN: usize = 8;

/// Payload bytes per segment. `Le` maxes out at 65535 and covers itself plus
/// the JPEG XT header and the repeated JUMBF header, so the true ceiling is
/// 65533 - 16 = 65517. Rounding down to 64000 leaves room to spare and matches
/// what `c2pa-rs` writes.
const MAX_SEGMENT_PAYLOAD: usize = 64000;

#[derive(Debug)]
pub struct JpegError(String);

impl fmt::Display for JpegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for JpegError {}

type Result<T> = std::result::Result<T, JpegError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(JpegError(message.into()))
}

/// One marker segment located in a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub marker: u8,
    /// Offset of the `FF` byte.
    pub start: usize,
    /// Offset one past the segment's last byte, length field included.
    pub end: usize,
}

impl Segment {
    /// Bytes on the wire, marker and length field included.
    pub fn byte_len(&self) -> usize {
        self.end - self.start
    }
}

/// Walk the marker segments ahead of the entropy-coded data.
///
/// Scanning stops at `SOS`: everything after it is compressed scan data, in
/// which `FF` bytes are byte-stuffed rather than markers, and a C2PA manifest
/// never lives there.
pub fn segments(bytes: &[u8]) -> Result<Vec<Segment>> {
    if bytes.len() < 2 || bytes[0] != MARKER_PREFIX || bytes[1] != SOI {
        return err("not a JPEG: the file does not start with SOI");
    }

    let mut found = Vec::new();
    let mut at = 2;

    while at + 1 < bytes.len() {
        if bytes[at] != MARKER_PREFIX {
            return err(format!("expected a marker at byte {at}"));
        }

        // Any number of FF bytes may pad the space before a marker.
        let mut marker_at = at;
        while marker_at < bytes.len() && bytes[marker_at] == MARKER_PREFIX {
            marker_at += 1;
        }
        let Some(&marker) = bytes.get(marker_at) else {
            return err("file ends in the middle of a marker");
        };

        // Standalone markers: no length field follows. SOI/EOI, the restart
        // markers RST0..RST7, and TEM.
        if marker == SOI || marker == EOI || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            at = marker_at + 1;
            if marker == EOI {
                break;
            }
            continue;
        }

        let length_at = marker_at + 1;
        if length_at + 1 >= bytes.len() {
            return err(format!("segment FF{marker:02X} has no length field"));
        }
        let length = u16::from_be_bytes([bytes[length_at], bytes[length_at + 1]]) as usize;
        if length < 2 {
            return err(format!("segment FF{marker:02X} declares an invalid length"));
        }
        let end = length_at + length;
        if end > bytes.len() {
            return err(format!(
                "segment FF{marker:02X} runs past the end of the file"
            ));
        }

        found.push(Segment {
            marker,
            start: marker_at - 1,
            end,
        });

        if marker == SOS {
            break;
        }
        at = end;
    }

    Ok(found)
}

/// The bytes of a segment after its marker and `Le`.
fn contents<'a>(bytes: &'a [u8], segment: &Segment) -> &'a [u8] {
    &bytes[segment.start + 4..segment.end]
}

/// Whether an `APP11` segment *starts* a C2PA manifest store.
///
/// A JPEG may hold `APP11` segments for unrelated standards — JPEG 360 and JPEG
/// Privacy and Security both use them — so the check is on the JUMBF type UUID
/// of the box, whose first four bytes read `c2pa`.
///
/// Only the first segment of a store can be recognised this way. Continuation
/// segments repeat `LBox`/`TBox` but carry raw manifest bytes after them, not a
/// description box, so they are matched by their box instance number instead.
fn starts_c2pa_store(bytes: &[u8], segment: &Segment) -> bool {
    if segment.marker != APP11 {
        return false;
    }
    // `contents` starts just past the marker and Le, so it is laid out as:
    //
    //   0..2   CI = "JP"        12..16  TBox = "jumb"
    //   2..4   En               16..20  the description box's LBox
    //   4..8   Z                20..24  its TBox = "jumd"
    //   8..12  LBox             24..28  the first four bytes of the type UUID,
    //                                   which read "c2pa" for a manifest store
    let contents = contents(bytes, segment);
    if contents.len() < 28 || contents[..2] != CI_JP {
        return false;
    }
    &contents[12..16] == b"jumb" && &contents[20..24] == b"jumd" && &contents[24..28] == b"c2pa"
}

/// The box instance number of a JPEG XT segment.
fn box_instance(bytes: &[u8], segment: &Segment) -> Option<[u8; 2]> {
    let contents = contents(bytes, segment);
    if segment.marker != APP11 || contents.len() < XT_HEADER_LEN || contents[..2] != CI_JP {
        return None;
    }
    Some([contents[2], contents[3]])
}

/// Every segment belonging to the C2PA manifest store, in file order.
///
/// The first is found by its JUMBF type UUID; the rest are the `APP11` segments
/// that immediately follow it and share its box instance number. Requiring both
/// adjacency and a matching `En` is what keeps an unrelated `APP11` from being
/// swallowed into the store, and matches the requirement in section A.3.1 that
/// the segments be written contiguously and in order.
fn store_segments(bytes: &[u8], all: &[Segment]) -> Vec<Segment> {
    let Some(first) = all.iter().position(|s| starts_c2pa_store(bytes, s)) else {
        return Vec::new();
    };

    let instance = box_instance(bytes, &all[first]);
    let mut found = vec![all[first]];
    let mut expected = all[first].end;

    for segment in &all[first + 1..] {
        if segment.start != expected
            || segment.marker != APP11
            || box_instance(bytes, segment) != instance
        {
            break;
        }
        found.push(*segment);
        expected = segment.end;
    }

    found
}

/// Where a manifest store sits in a file, and the store itself.
#[derive(Debug)]
pub struct EmbeddedStore {
    /// The reassembled JUMBF manifest store.
    pub store: Vec<u8>,
    /// First byte of the first C2PA `APP11` segment: the exclusion's `start`.
    pub start: usize,
    /// Total bytes across every C2PA `APP11` segment: the exclusion's `length`.
    pub length: usize,
}

/// Pull a C2PA manifest store back out of a JPEG.
///
/// Returns `Ok(None)` for a JPEG that simply has no manifest, which is the
/// common case and not an error.
pub fn extract(bytes: &[u8]) -> Result<Option<EmbeddedStore>> {
    let all = segments(bytes)?;
    let c2pa = store_segments(bytes, &all);

    let Some(first) = c2pa.first() else {
        return Ok(None);
    };
    let end = c2pa.last().map(|s| s.end).unwrap_or(first.end);

    let mut store = Vec::new();
    for (index, segment) in c2pa.iter().enumerate() {
        let contents = contents(bytes, segment);
        // The first segment's payload begins at LBox, which is part of the
        // store. Later segments repeat LBox/TBox, and that copy is framing.
        let skip = if index == 0 {
            XT_HEADER_LEN
        } else {
            XT_HEADER_LEN + JUMBF_HEADER_LEN
        };
        if contents.len() < skip {
            return err("a C2PA APP11 segment is too short to hold its header");
        }
        store.extend_from_slice(&contents[skip..]);
    }

    // The store's own LBox is the authority on where it ends. Trailing bytes
    // are padding inside the last segment, not manifest data.
    if store.len() >= 4 {
        let declared = u32::from_be_bytes([store[0], store[1], store[2], store[3]]) as usize;
        if declared >= 8 && declared <= store.len() {
            store.truncate(declared);
        }
    }

    Ok(Some(EmbeddedStore {
        store,
        start: first.start,
        length: end - first.start,
    }))
}

/// Total bytes an `APP11` embedding of `store_len` will occupy.
///
/// The claim generator needs this before it has a store to embed, because the
/// hard binding has to declare the exclusion range that the store will end up
/// living in. Keeping the arithmetic in one place, used by both the size
/// prediction and the writer, is what makes the prediction trustworthy.
pub fn embedded_length(store_len: usize) -> usize {
    let segments = store_len.div_ceil(MAX_SEGMENT_PAYLOAD).max(1);
    // Per segment: marker(2) + Le(2) + CI(2) + En(2) + Z(4). Continuation
    // segments additionally repeat LBox/TBox.
    let framing = segments * (4 + XT_HEADER_LEN) + (segments - 1) * JUMBF_HEADER_LEN;
    framing + store_len
}

/// Serialise a manifest store as a run of `APP11` segments.
pub fn segments_for(store: &[u8]) -> Result<Vec<u8>> {
    if store.len() < JUMBF_HEADER_LEN {
        return err("manifest store is too short to be a JUMBF box");
    }

    let mut out = Vec::with_capacity(embedded_length(store.len()));
    for (index, chunk) in store.chunks(MAX_SEGMENT_PAYLOAD).enumerate() {
        let payload_len = chunk.len() + if index == 0 { 0 } else { JUMBF_HEADER_LEN };
        // Le covers itself, the JPEG XT header and the payload.
        let le = 2 + XT_HEADER_LEN + payload_len;
        debug_assert!(le <= u16::MAX as usize, "segment length must fit in Le");

        out.push(MARKER_PREFIX);
        out.push(APP11);
        out.extend_from_slice(&(le as u16).to_be_bytes());
        out.extend_from_slice(&CI_JP);
        out.extend_from_slice(&BOX_INSTANCE);
        // Z numbers packets from 1.
        out.extend_from_slice(&(index as u32 + 1).to_be_bytes());
        if index > 0 {
            out.extend_from_slice(&store[..JUMBF_HEADER_LEN]);
        }
        out.extend_from_slice(chunk);
    }

    debug_assert_eq!(out.len(), embedded_length(store.len()));
    Ok(out)
}

/// Where a new manifest store should go, and the file with any previous one
/// taken out.
#[derive(Debug)]
pub struct InsertionPlan {
    /// The file with existing C2PA `APP11` segments removed.
    pub stripped: Vec<u8>,
    /// Byte offset in `stripped` at which to splice the new segments.
    pub offset: usize,
}

/// Decide where a manifest goes.
///
/// It lands immediately after the `JFIF` `APP0` segment when there is one, and
/// straight after `SOI` otherwise. `APP0` has to stay first for decoders that
/// identify a JFIF file by finding it there.
pub fn plan_insertion(bytes: &[u8]) -> Result<InsertionPlan> {
    let all = segments(bytes)?;

    // Drop any manifest already present. Signing an image twice should replace
    // the credential, not stack a second one that hashes over the first.
    let existing = store_segments(bytes, &all);

    let mut stripped = Vec::with_capacity(bytes.len());
    let mut at = 0;
    for segment in &existing {
        stripped.extend_from_slice(&bytes[at..segment.start]);
        at = segment.end;
    }
    stripped.extend_from_slice(&bytes[at..]);

    // Offsets shift once segments are removed, so the insertion point is found
    // in the stripped file rather than translated from the original.
    let offset = segments(&stripped)?
        .iter()
        .filter(|s| s.marker == APP0)
        .map(|s| s.end)
        .next_back()
        .unwrap_or(2);

    Ok(InsertionPlan { stripped, offset })
}

/// Splice `store` into `plan.stripped` at `plan.offset`.
pub fn embed(plan: &InsertionPlan, store: &[u8]) -> Result<Vec<u8>> {
    let app11 = segments_for(store)?;
    let mut out = Vec::with_capacity(plan.stripped.len() + app11.len());
    out.extend_from_slice(&plan.stripped[..plan.offset]);
    out.extend_from_slice(&app11);
    out.extend_from_slice(&plan.stripped[plan.offset..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but structurally valid JPEG: SOI, a JFIF APP0, a comment and
    /// EOI. Enough for the segment walker; no decoder ever sees it.
    fn stub_jpeg() -> Vec<u8> {
        let mut jpeg = vec![0xFF, SOI];
        let jfif = b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0";
        jpeg.extend_from_slice(&[0xFF, APP0]);
        jpeg.extend_from_slice(&((jfif.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(jfif);
        jpeg.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x05, b'h', b'i', b'!']);
        jpeg.extend_from_slice(&[0xFF, EOI]);
        jpeg
    }

    /// A JUMBF store whose description box announces the c2pa UUID, so the
    /// APP11 detector recognises it.
    fn stub_store(payload_len: usize) -> Vec<u8> {
        let mut description = Vec::new();
        description.extend_from_slice(&crate::c2pa::jumbf::UUID_MANIFEST_STORE);
        description.push(0x03);
        description.extend_from_slice(b"c2pa\0");

        let mut jumd = Vec::new();
        jumd.extend_from_slice(&((description.len() + 8) as u32).to_be_bytes());
        jumd.extend_from_slice(b"jumd");
        jumd.extend_from_slice(&description);

        let mut store = Vec::new();
        store.extend_from_slice(&((jumd.len() + 8 + payload_len) as u32).to_be_bytes());
        store.extend_from_slice(b"jumb");
        store.extend_from_slice(&jumd);
        store.extend(std::iter::repeat_n(0xAB, payload_len));
        store
    }

    #[test]
    fn walks_marker_segments() {
        let found = segments(&stub_jpeg()).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].marker, APP0);
        assert_eq!(found[1].marker, 0xFE);
    }

    #[test]
    fn rejects_input_that_is_not_a_jpeg() {
        assert!(segments(b"\x89PNG\r\n\x1a\n").is_err());
        assert!(segments(&[]).is_err());
    }

    #[test]
    fn manifests_land_after_the_jfif_header() {
        // A decoder identifies a JFIF file by APP0 being the first segment, so
        // a manifest inserted ahead of it would change how the file is read.
        let plan = plan_insertion(&stub_jpeg()).unwrap();
        let app0 = segments(&stub_jpeg()).unwrap()[0];
        assert_eq!(plan.offset, app0.end);
    }

    #[test]
    fn manifests_land_after_soi_when_there_is_no_app0() {
        let bare = vec![0xFF, SOI, 0xFF, 0xFE, 0x00, 0x03, b'x', 0xFF, EOI];
        assert_eq!(plan_insertion(&bare).unwrap().offset, 2);
    }

    #[test]
    fn round_trips_a_store_through_a_jpeg() {
        let store = stub_store(64);
        let plan = plan_insertion(&stub_jpeg()).unwrap();
        let signed = embed(&plan, &store).unwrap();

        let found = extract(&signed).unwrap().expect("a store");
        assert_eq!(found.store, store);
        assert_eq!(found.start, plan.offset);
        assert_eq!(found.length, embedded_length(store.len()));
        // What was excised is exactly what was inserted.
        let mut without = signed[..found.start].to_vec();
        without.extend_from_slice(&signed[found.start + found.length..]);
        assert_eq!(without, plan.stripped);
    }

    #[test]
    fn round_trips_a_store_that_needs_several_segments() {
        // Three segments' worth, so both the continuation framing and the
        // repeated LBox/TBox get exercised.
        let store = stub_store(MAX_SEGMENT_PAYLOAD * 2 + 1234);
        let plan = plan_insertion(&stub_jpeg()).unwrap();
        let signed = embed(&plan, &store).unwrap();

        let app11 = segments(&signed)
            .unwrap()
            .iter()
            .filter(|s| s.marker == APP11)
            .count();
        assert_eq!(app11, 3);

        let found = extract(&signed).unwrap().expect("a store");
        assert_eq!(found.store, store);
        assert_eq!(found.length, embedded_length(store.len()));
    }

    #[test]
    fn predicted_length_matches_what_is_written() {
        // The hard binding declares this length before the store exists, so a
        // mismatch here would mean every multi-segment manifest fails to
        // validate.
        for payload in [0, 1, 100, MAX_SEGMENT_PAYLOAD - 20, MAX_SEGMENT_PAYLOAD * 3] {
            let store = stub_store(payload);
            let written = segments_for(&store).unwrap();
            assert_eq!(
                written.len(),
                embedded_length(store.len()),
                "prediction wrong for a {payload}-byte payload"
            );
        }
    }

    #[test]
    fn every_segment_length_fits_in_le() {
        let store = stub_store(MAX_SEGMENT_PAYLOAD * 2);
        let plan = plan_insertion(&stub_jpeg()).unwrap();
        let signed = embed(&plan, &store).unwrap();
        for segment in segments(&signed).unwrap() {
            assert!(segment.byte_len() <= 65535 + 2, "segment overflows Le");
        }
    }

    #[test]
    fn signing_twice_replaces_rather_than_stacks() {
        let plan = plan_insertion(&stub_jpeg()).unwrap();
        let once = embed(&plan, &stub_store(64)).unwrap();

        let replan = plan_insertion(&once).unwrap();
        assert_eq!(
            replan.stripped, plan.stripped,
            "stripping should recover the unsigned file exactly"
        );
        let twice = embed(&replan, &stub_store(128)).unwrap();

        assert_eq!(extract(&twice).unwrap().unwrap().store, stub_store(128));
        let app11 = segments(&twice)
            .unwrap()
            .iter()
            .filter(|s| s.marker == APP11)
            .count();
        assert_eq!(app11, 1, "the first manifest should be gone, not kept");
    }

    #[test]
    fn ignores_app11_segments_that_are_not_c2pa() {
        // JPEG 360 and JPEG Privacy and Security also use APP11; treating one
        // as a manifest would corrupt both it and the hard binding.
        let mut jpeg = vec![0xFF, SOI];
        let body = b"JP\x00\x01\x00\x00\x00\x01somethingelseentirely!!!!!!!!";
        jpeg.extend_from_slice(&[0xFF, APP11]);
        jpeg.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(body);
        jpeg.extend_from_slice(&[0xFF, EOI]);

        assert!(extract(&jpeg).unwrap().is_none());
        // ...and it survives signing untouched.
        let plan = plan_insertion(&jpeg).unwrap();
        assert_eq!(plan.stripped, jpeg);
    }

    #[test]
    fn no_manifest_is_not_an_error() {
        assert!(extract(&stub_jpeg()).unwrap().is_none());
    }
}
