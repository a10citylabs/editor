//! End-to-end tests for the Content Credentials pipeline.
//!
//! The unit tests inside each module check one layer at a time. These check the
//! thing that actually matters: that a JPEG signed by this engine validates
//! when read back, that tampering with it stops validating, and that a second
//! edit chains onto the first instead of erasing it.

use image::{ImageFormat, Rgb, RgbImage};
use imagecore::c2pa::{self, manifest, SignRequest};
use imagecore::pipeline::{AdjustSpec, Crop, Pipeline, Resize};
use std::io::Cursor;

/// A JPEG with enough structure to be worth hashing. A flat colour compresses
/// to almost nothing, which would not exercise the multi-byte length paths.
fn jpeg(width: u32, height: u32) -> Vec<u8> {
    let image = RgbImage::from_fn(width, height, |x, y| {
        Rgb([
            (x * 7 % 256) as u8,
            (y * 11 % 256) as u8,
            ((x + y) * 13 % 256) as u8,
        ])
    });
    let mut bytes = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Jpeg)
        .expect("encoding a JPEG");
    bytes
}

/// A request with every non-deterministic value pinned, so tests are stable.
fn request(title: &str) -> SignRequest {
    SignRequest {
        title: title.to_string(),
        generator: c2pa::generator(),
        now: "2026-08-25T12:00:00Z".to_string(),
        instance_id: "xmp:iid:11111111-2222-3333-4444-555555555555".to_string(),
        manifest_id: "urn:c2pa:AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE".to_string(),
        actions: Vec::new(),
        parent: None,
        thumbnail: None,
    }
}

fn edited_pipeline() -> Pipeline {
    Pipeline {
        crop: Some(Crop {
            x: 8,
            y: 12,
            width: 160,
            height: 120,
        }),
        quarter_turns: 1,
        resize: Some(Resize {
            width: 80,
            height: 60,
            filter: "lanczos3".into(),
        }),
        adjust: AdjustSpec {
            saturation: -0.4,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn a_signed_jpeg_validates() {
    let source = jpeg(320, 240);
    let mut request = request("holiday.jpg");
    request.actions = c2pa::actions_for(&edited_pipeline(), true, (80, 60));
    request.parent = Some(manifest::Parent {
        title: "original.jpg".into(),
        format: "image/jpeg".into(),
        instance_id: "xmp:iid:original".into(),
        store: None,
    });

    let signed = c2pa::sign_jpeg(&source, &request).expect("signing");
    let report = c2pa::read_jpeg(&signed.jpeg)
        .expect("reading")
        .expect("the signed file should carry a manifest");

    assert!(
        report.is_valid(),
        "a freshly signed file must validate; failures: {:?}",
        report.active.status.failure
    );

    // The three checks that matter, each reported by its specification code.
    let codes: Vec<&str> = report
        .active
        .status
        .success
        .iter()
        .map(|s| s.code.as_str())
        .collect();
    assert!(codes.contains(&"assertion.dataHash.match"), "{codes:?}");
    assert!(codes.contains(&"assertion.hashedURI.match"), "{codes:?}");
    assert!(codes.contains(&"claimSignature.validated"), "{codes:?}");

    assert_eq!(report.active.title, "holiday.jpg");
    assert_eq!(report.active.claim_version, 2);
    assert!(report.active.generator.starts_with("A10city Image Editor"));
    assert_eq!(report.active.signature.algorithm, "ES256");
}

#[test]
fn the_signed_file_is_still_a_readable_jpeg() {
    // A credential nobody can open is worse than no credential.
    let source = jpeg(200, 150);
    let signed = c2pa::sign_jpeg(&source, &request("photo.jpg")).unwrap();

    let decoded = image::load_from_memory_with_format(&signed.jpeg, ImageFormat::Jpeg)
        .expect("a signed JPEG must still decode");
    assert_eq!((decoded.width(), decoded.height()), (200, 150));

    let original = image::load_from_memory_with_format(&source, ImageFormat::Jpeg).unwrap();
    assert_eq!(
        decoded.to_rgb8().into_raw(),
        original.to_rgb8().into_raw(),
        "embedding a manifest must not touch a single pixel"
    );
}

#[test]
fn the_actions_survive_the_round_trip() {
    let mut request = request("edited.jpg");
    request.actions = c2pa::actions_for(&edited_pipeline(), true, (80, 60));

    let signed = c2pa::sign_jpeg(&jpeg(320, 240), &request).unwrap();
    let report = c2pa::read_jpeg(&signed.jpeg).unwrap().unwrap();

    let names: Vec<&str> = report
        .active
        .actions
        .iter()
        .map(|a| a.action.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "c2pa.opened",
            "c2pa.orientation",
            "c2pa.cropped",
            "c2pa.resized",
            "c2pa.adjustedColor",
        ]
    );

    // Descriptions are the part a person actually reads.
    let crop = report
        .active
        .actions
        .iter()
        .find(|a| a.action == "c2pa.cropped")
        .unwrap();
    assert_eq!(crop.description, "cropped to 160x120 at (8, 12)");
    assert_eq!(crop.when, "2026-08-25T12:00:00Z");
    assert!(crop.software_agent.starts_with("A10city Image Editor"));
}

#[test]
fn tampering_with_the_pixels_is_caught() {
    let signed = c2pa::sign_jpeg(&jpeg(200, 150), &request("photo.jpg")).unwrap();

    // Flip a byte deep in the entropy-coded scan data, well past any header.
    let mut tampered = signed.jpeg.clone();
    let target = tampered.len() - 32;
    tampered[target] ^= 0xFF;

    let report = c2pa::read_jpeg(&tampered).unwrap().unwrap();
    assert!(!report.is_valid(), "a modified image must not validate");
    assert!(
        report
            .active
            .status
            .failure
            .iter()
            .any(|s| s.code == "assertion.dataHash.mismatch"),
        "expected a data hash mismatch, got {:?}",
        report.active.status.failure
    );
}

#[test]
fn tampering_with_an_assertion_is_caught() {
    // Rewriting an action inside the manifest leaves the image bytes alone, so
    // only the assertion's hashed URI catches it.
    let signed = c2pa::sign_jpeg(&jpeg(200, 150), &{
        let mut request = request("photo.jpg");
        request.actions = vec![manifest::Action::new("c2pa.cropped").describe("cropped to A")];
        request
    })
    .unwrap();

    let needle = b"cropped to A";
    let at = signed
        .jpeg
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the description should be findable in the manifest");

    let mut tampered = signed.jpeg.clone();
    tampered[at + needle.len() - 1] = b'B';

    let report = c2pa::read_jpeg(&tampered).unwrap().unwrap();
    assert!(!report.is_valid());
    assert!(
        report
            .active
            .status
            .failure
            .iter()
            .any(|s| s.code == "assertion.hashedURI.mismatch"),
        "expected a hashed URI mismatch, got {:?}",
        report.active.status.failure
    );
}

#[test]
fn tampering_with_the_claim_is_caught_by_the_signature() {
    let signed = c2pa::sign_jpeg(&jpeg(200, 150), &request("truthful-title.jpg")).unwrap();

    let needle = b"truthful-title.jpg";
    let at = signed
        .jpeg
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("dc:title should be in the claim");

    let mut tampered = signed.jpeg.clone();
    tampered[at] = b'T';

    let report = c2pa::read_jpeg(&tampered).unwrap().unwrap();
    assert!(!report.is_valid());
    assert!(
        report
            .active
            .status
            .failure
            .iter()
            .any(|s| s.code == "claimSignature.mismatch"),
        "expected a signature mismatch, got {:?}",
        report.active.status.failure
    );
}

#[test]
fn a_second_edit_chains_onto_the_first() {
    // The point of provenance: editing an already-credentialed image should
    // carry its history forward rather than starting over.
    let first = c2pa::sign_jpeg(&jpeg(320, 240), &{
        let mut request = request("original.jpg");
        request.actions = vec![manifest::Action::new("c2pa.created")];
        request
    })
    .unwrap();

    let parent_report = c2pa::read_jpeg(&first.jpeg).unwrap().unwrap();
    assert!(parent_report.is_valid());

    let mut second = request("edited.jpg");
    second.manifest_id = "urn:c2pa:99999999-8888-4777-8666-555555555555".into();
    second.instance_id = "xmp:iid:second".into();
    second.actions = c2pa::actions_for(&edited_pipeline(), true, (80, 60));
    second.parent = Some(manifest::Parent {
        title: "original.jpg".into(),
        format: "image/jpeg".into(),
        instance_id: parent_report.active.instance_id.clone(),
        store: Some(manifest::ParentStore {
            bytes: parent_report.store.clone(),
            active_manifest: parent_report.active.label.clone(),
            status: parent_report.active.status.clone(),
        }),
    });

    // The second edit is applied to a re-encode of the first, as the real
    // pipeline does; the credential describes the new bytes.
    let signed = c2pa::sign_jpeg(&jpeg(80, 60), &second).unwrap();
    let report = c2pa::read_jpeg(&signed.jpeg).unwrap().unwrap();

    assert!(
        report.is_valid(),
        "failures: {:?}",
        report.active.status.failure
    );
    assert_eq!(report.chain.len(), 2, "both manifests should be present");
    assert_eq!(report.chain[0].title, "original.jpg");
    assert_eq!(report.chain[1].title, "edited.jpg");
    assert_eq!(
        report.active.label, second.manifest_id,
        "the active manifest is the last one in the store"
    );

    // The ingredient links the new manifest back to the old one.
    assert_eq!(report.active.ingredients.len(), 1);
    let ingredient = &report.active.ingredients[0];
    assert_eq!(ingredient.relationship, "parentOf");
    assert_eq!(ingredient.title, "original.jpg");
    assert!(
        ingredient.has_manifest,
        "the ingredient should point at the parent's manifest"
    );

    // The inherited manifest still validates on its own terms: its assertions
    // and signature are intact after being copied forward.
    assert!(
        report.chain[0].status.failure.is_empty(),
        "the inherited manifest should survive the copy: {:?}",
        report.chain[0].status.failure
    );
}

#[test]
fn re_signing_replaces_the_credential() {
    let once = c2pa::sign_jpeg(&jpeg(200, 150), &request("first.jpg")).unwrap();
    let twice = c2pa::sign_jpeg(&once.jpeg, &request("second.jpg")).unwrap();

    let report = c2pa::read_jpeg(&twice.jpeg).unwrap().unwrap();
    assert!(
        report.is_valid(),
        "re-signing must produce a valid file; failures: {:?}",
        report.active.status.failure
    );
    assert_eq!(report.chain.len(), 1, "the old manifest should be replaced");
    assert_eq!(report.active.title, "second.jpg");
}

#[test]
fn a_thumbnail_survives_the_round_trip() {
    let thumbnail = jpeg(64, 48);
    let mut request = request("photo.jpg");
    request.thumbnail = Some(thumbnail.clone());

    let signed = c2pa::sign_jpeg(&jpeg(200, 150), &request).unwrap();
    let report = c2pa::read_jpeg(&signed.jpeg).unwrap().unwrap();

    assert!(report.is_valid());
    assert_eq!(report.active.thumbnail.as_ref(), Some(&thumbnail));
    assert!(report
        .active
        .assertion_labels
        .contains(&"c2pa.thumbnail.claim".to_string()));
}

#[test]
fn a_manifest_that_spans_several_app11_segments_validates() {
    // A thumbnail large enough to push the store past the 64000-byte segment
    // limit, exercising the continuation framing end to end.
    let mut request = request("large.jpg");
    request.thumbnail = Some(jpeg(900, 700));

    let signed = c2pa::sign_jpeg(&jpeg(200, 150), &request).unwrap();
    assert!(
        signed.manifest_len > 64_000,
        "expected a multi-segment manifest, got {} bytes",
        signed.manifest_len
    );

    let report = c2pa::read_jpeg(&signed.jpeg).unwrap().unwrap();
    assert!(
        report.is_valid(),
        "failures: {:?}",
        report.active.status.failure
    );
}

#[test]
fn an_unsigned_jpeg_reports_no_credentials() {
    assert!(c2pa::read_jpeg(&jpeg(64, 64)).unwrap().is_none());
}

#[test]
fn the_exclusion_range_is_exactly_the_manifest() {
    // If the excluded range were even a byte off, the hard binding would either
    // hash part of its own manifest or leave image bytes unprotected.
    let signed = c2pa::sign_jpeg(&jpeg(200, 150), &request("photo.jpg")).unwrap();
    let report = c2pa::read_jpeg(&signed.jpeg).unwrap().unwrap();

    assert!(report.is_valid());
    assert_eq!(report.store_len, signed.embedded_len);

    // Removing exactly the declared range must give back the unsigned file.
    let extracted = imagecore::c2pa::jpegxt::extract(&signed.jpeg)
        .unwrap()
        .unwrap();
    let mut without = signed.jpeg[..extracted.start].to_vec();
    without.extend_from_slice(&signed.jpeg[extracted.start + extracted.length..]);
    assert_eq!(without, jpeg(200, 150));
}

#[test]
fn widening_the_exclusion_range_is_rejected() {
    // The attack the exclusion check exists for: claim a bigger excluded region
    // and hide a change to the image inside it.
    let signed = c2pa::sign_jpeg(&jpeg(200, 150), &request("photo.jpg")).unwrap();
    let extracted = imagecore::c2pa::jpegxt::extract(&signed.jpeg)
        .unwrap()
        .unwrap();

    // The exclusion is written as a fixed-width 32-bit integer, so its length
    // field can be found and rewritten without disturbing anything else.
    let needle = (extracted.length as u32).to_be_bytes();
    let at = signed
        .jpeg
        .windows(4)
        .position(|w| w == needle)
        .expect("the exclusion length should be in the manifest");

    let mut tampered = signed.jpeg.clone();
    tampered[at..at + 4].copy_from_slice(&(extracted.length as u32 + 64).to_be_bytes());

    let report = c2pa::read_jpeg(&tampered).unwrap().unwrap();
    assert!(!report.is_valid(), "a widened exclusion must be rejected");
    assert!(report
        .active
        .status
        .failure
        .iter()
        .any(|s| s.code.starts_with("assertion.")));
}

#[test]
fn signing_the_same_input_twice_is_byte_identical() {
    // Deterministic CBOR plus RFC 6979 signatures. Worth pinning: it is what
    // makes every other test here reproducible, and it means a rebuild of the
    // same edit produces the same file rather than a gratuitously new one.
    let source = jpeg(200, 150);
    let first = c2pa::sign_jpeg(&source, &request("photo.jpg")).unwrap();
    let second = c2pa::sign_jpeg(&source, &request("photo.jpg")).unwrap();
    assert_eq!(first.jpeg, second.jpeg);
}

#[test]
fn the_signer_reports_itself_as_untrusted() {
    // The UI depends on this being visible rather than inferred.
    let signed = c2pa::sign_jpeg(&jpeg(120, 90), &request("photo.jpg")).unwrap();
    let report = c2pa::read_jpeg(&signed.jpeg).unwrap().unwrap();

    assert!(
        report
            .active
            .status
            .informational
            .iter()
            .any(|s| s.code == "signingCredential.untrusted"),
        "validation must say the signer was never checked against a trust list"
    );
    assert!(!report.active.signature.time_stamped);
    assert!(report.active.signature.subject.contains("Untrusted"));
}
