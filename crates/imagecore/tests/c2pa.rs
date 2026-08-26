//! End-to-end tests for the Content Credentials pipeline.
//!
//! The unit tests inside each module check one layer at a time. These check the
//! thing that actually matters: that a JPEG signed by this engine validates
//! when read back, that tampering with it stops validating, that the signer
//! chains to a trust anchor, that a time-stamp outlives the certificate, and
//! that a second edit chains onto the first instead of erasing it.
//!
//! # Standing in for the Backend
//!
//! Signing is a network call in production: the Edge hands over a
//! `Sig_structure`, `services/claim-signer` returns a signature and a
//! time-stamp. [`sign`] below does the same thing with the test key in-process.
//! The seam it exercises is the real one — `prepare` and `complete` are the
//! same functions the browser calls — so nothing about the two-phase flow is
//! mocked away.

use image::{ImageFormat, Rgb, RgbImage};
use imagecore::c2pa::{
    self, clock, manifest, testpki, SignRequest, Signed, TrustStore, ValidationOptions,
};
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

/// Sign as the Backend subsystem would, with no time-stamp.
fn sign(jpeg: &[u8], request: &SignRequest) -> Signed {
    sign_with(jpeg, request, testpki::identity_without_timestamps(), false)
}

/// Sign and time-stamp, as a Backend with a configured TSA would.
fn sign_timestamped(jpeg: &[u8], request: &SignRequest) -> Signed {
    sign_with(jpeg, request, testpki::identity(), true)
}

fn sign_with(
    jpeg: &[u8],
    request: &SignRequest,
    identity: c2pa::SigningIdentity,
    timestamp: bool,
) -> Signed {
    let prepared =
        manifest::prepare(jpeg, request.clone(), identity).expect("preparing the manifest");

    // What crosses the wire, and all that crosses it.
    let signature = testpki::sign_es256(&prepared.to_be_signed);

    // RFC 3161 stamps the signature, not the claim.
    let token = timestamp.then(|| testpki::issue_timestamp(&signature, testpki::validation_time()));

    manifest::complete(&prepared, &signature, token.as_deref()).expect("completing the manifest")
}

/// Validation with the test trust lists, at a time inside the certificate's
/// window.
fn trusting() -> ValidationOptions {
    ValidationOptions {
        trust: TrustStore::from_pem(testpki::TRUST_LIST_PEM).unwrap().0,
        tsa_trust: TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap().0,
        validation_time: testpki::validation_time(),
    }
}

/// Validation with no trust lists, which is what a browser with no list
/// configured does.
fn untrusting() -> ValidationOptions {
    ValidationOptions::untrusted(testpki::validation_time())
}

fn read(jpeg: &[u8], options: &ValidationOptions) -> c2pa::ValidationReport {
    c2pa::validate_jpeg(jpeg, options)
        .expect("reading")
        .expect("the signed file should carry a manifest")
}

fn codes(status: &[manifest::Status]) -> Vec<&str> {
    status.iter().map(|s| s.code.as_str()).collect()
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

    let signed = sign(&source, &request);
    let report = read(&signed.jpeg, &trusting());

    assert!(
        report.is_valid(),
        "a freshly signed file must validate; failures: {:?}",
        report.active.status.failure
    );

    // Every check that matters, each reported by its specification code.
    let success = codes(&report.active.status.success);
    assert!(success.contains(&"assertion.dataHash.match"), "{success:?}");
    assert!(
        success.contains(&"assertion.hashedURI.match"),
        "{success:?}"
    );
    assert!(success.contains(&"claimSignature.validated"), "{success:?}");
    assert!(
        success.contains(&"signingCredential.trusted"),
        "{success:?}"
    );
    assert!(
        success.contains(&"claimSignature.insideValidity"),
        "{success:?}"
    );

    assert_eq!(report.active.title, "holiday.jpg");
    assert_eq!(report.active.claim_version, 2);
    assert!(report.active.generator.starts_with("A10city Image Editor"));
    assert_eq!(report.active.signature.algorithm, "ES256");
}

#[test]
fn the_claim_declares_the_specification_version_it_was_built_to() {
    // A Conformance Program requirement: the value has to match the product's
    // Conforming Products List record.
    let signed = sign(&jpeg(160, 120), &request("photo.jpg"));
    let report = read(&signed.jpeg, &untrusting());
    assert_eq!(report.active.spec_version, c2pa::SPEC_VERSION);
}

#[test]
fn the_actions_assertion_declares_that_it_is_complete() {
    // allActionsIncluded is optional in the specification and mandatory under
    // the Conformance Program, because an asset rubric cannot classify
    // provenance that might be missing steps.
    let mut request = request("edited.jpg");
    request.actions = c2pa::actions_for(&edited_pipeline(), true, (80, 60));
    let signed = sign(&jpeg(320, 240), &request);
    let report = read(&signed.jpeg, &untrusting());

    let (_, actions) = report
        .active
        .raw
        .assertions
        .iter()
        .find(|(label, _)| label == "c2pa.actions.v2")
        .expect("the actions assertion should be present");
    let actions = actions.as_ref().expect("it should decode");
    assert_eq!(
        actions.get("allActionsIncluded"),
        Some(&imagecore::c2pa::cbor::Value::Bool(true))
    );
}

#[test]
fn every_action_that_needs_a_digital_source_type_carries_one_in_the_file() {
    // Checked on the way back out, not just on the way in: a field that is
    // dropped by the encoder would pass the unit test and fail conformance.
    let mut request = request("edited.jpg");
    request.actions = c2pa::actions_for(&edited_pipeline(), true, (80, 60));
    let signed = sign(&jpeg(320, 240), &request);
    let report = read(&signed.jpeg, &untrusting());

    for action in &report.active.actions {
        if c2pa::requires_digital_source_type(&action.action) {
            assert!(
                action
                    .digital_source_type
                    .starts_with("http://cv.iptc.org/"),
                "{} came back with digitalSourceType {:?}",
                action.action,
                action.digital_source_type
            );
        }
        if c2pa::forbids_digital_source_type(&action.action) {
            assert!(
                action.digital_source_type.is_empty(),
                "{} must not carry a digitalSourceType",
                action.action
            );
        }
    }
}

#[test]
fn the_signed_file_is_still_a_readable_jpeg() {
    // A credential nobody can open is worse than no credential.
    let source = jpeg(200, 150);
    let signed = sign(&source, &request("photo.jpg"));

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

    let signed = sign(&jpeg(320, 240), &request);
    let report = read(&signed.jpeg, &untrusting());

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
    let signed = sign(&jpeg(200, 150), &request("photo.jpg"));

    // Flip a byte deep in the entropy-coded scan data, well past any header.
    let mut tampered = signed.jpeg.clone();
    let target = tampered.len() - 32;
    tampered[target] ^= 0xFF;

    let report = read(&tampered, &trusting());
    assert!(!report.is_valid(), "a modified image must not validate");
    assert!(
        codes(&report.active.status.failure).contains(&"assertion.dataHash.mismatch"),
        "expected a data hash mismatch, got {:?}",
        report.active.status.failure
    );
}

#[test]
fn tampering_with_an_assertion_is_caught() {
    // Rewriting an action inside the manifest leaves the image bytes alone, so
    // only the assertion's hashed URI catches it.
    let signed = sign(&jpeg(200, 150), &{
        let mut request = request("photo.jpg");
        request.actions = vec![manifest::Action::new("c2pa.cropped").describe("cropped to A")];
        request
    });

    let needle = b"cropped to A";
    let at = signed
        .jpeg
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the description should be findable in the manifest");

    let mut tampered = signed.jpeg.clone();
    tampered[at + needle.len() - 1] = b'B';

    let report = read(&tampered, &trusting());
    assert!(!report.is_valid());
    assert!(
        codes(&report.active.status.failure).contains(&"assertion.hashedURI.mismatch"),
        "expected a hashed URI mismatch, got {:?}",
        report.active.status.failure
    );
}

#[test]
fn tampering_with_the_claim_is_caught_by_the_signature() {
    let signed = sign(&jpeg(200, 150), &request("truthful-title.jpg"));

    let needle = b"truthful-title.jpg";
    let at = signed
        .jpeg
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("dc:title should be in the claim");

    let mut tampered = signed.jpeg.clone();
    tampered[at] = b'T';

    let report = read(&tampered, &trusting());
    assert!(!report.is_valid());
    assert!(
        codes(&report.active.status.failure).contains(&"claimSignature.mismatch"),
        "expected a signature mismatch, got {:?}",
        report.active.status.failure
    );
}

/* -------------------------------------------------------------------------
Trust
------------------------------------------------------------------------- */

#[test]
fn a_signer_on_the_trust_list_is_reported_as_trusted() {
    let signed = sign(&jpeg(160, 120), &request("photo.jpg"));
    let report = read(&signed.jpeg, &trusting());

    assert!(report.active.signature.trusted);
    assert!(report
        .active
        .signature
        .trust_anchor
        .contains("Test Root CA"));
    // The two facts a relying party actually needs, straight from the
    // certificate rather than from anything the manifest says about itself.
    assert_eq!(report.active.signature.assurance_level, Some(1));
    assert_eq!(
        report.active.signature.cpl_record_id,
        "00000000-0000-0000-0000-000000000000"
    );
}

#[test]
fn a_signer_with_no_trust_list_is_reported_as_unchecked_not_as_failed() {
    // The distinction matters: "nobody looked" and "we looked and it failed"
    // call for different words in front of a reader.
    let signed = sign(&jpeg(160, 120), &request("photo.jpg"));
    let report = read(&signed.jpeg, &untrusting());

    assert!(!report.active.signature.trusted);
    assert!(
        report.is_valid(),
        "an unchecked signer is not a validation failure: {:?}",
        report.active.status.failure
    );
    assert!(codes(&report.active.status.informational).contains(&"signingCredential.untrusted"));
}

#[test]
fn a_signer_that_fails_against_a_supplied_trust_list_is_a_failure() {
    let signed = sign(&jpeg(160, 120), &request("photo.jpg"));
    // A real trust list that simply does not contain this signer's root.
    let options = ValidationOptions {
        trust: TrustStore::from_pem(testpki::TSA_TRUST_LIST_PEM).unwrap().0,
        tsa_trust: TrustStore::empty(),
        validation_time: testpki::validation_time(),
    };

    let report = read(&signed.jpeg, &options);
    assert!(!report.is_valid());
    assert!(codes(&report.active.status.failure).contains(&"signingCredential.untrusted"));
}

/* -------------------------------------------------------------------------
Time-stamps
------------------------------------------------------------------------- */

#[test]
fn a_time_stamped_credential_carries_its_attested_time() {
    let signed = sign_timestamped(&jpeg(200, 150), &request("photo.jpg"));
    assert!(signed.time_stamped);

    let report = read(&signed.jpeg, &trusting());
    assert!(
        report.is_valid(),
        "failures: {:?}",
        report.active.status.failure
    );
    assert!(report.active.signature.time_stamped);
    assert_eq!(
        report.active.signature.time_stamp,
        clock::to_rfc3339(testpki::validation_time())
    );
    let success = codes(&report.active.status.success);
    assert!(success.contains(&"timeStamp.trusted"), "{success:?}");
    assert!(success.contains(&"timeStamp.validated"), "{success:?}");
}

#[test]
fn a_time_stamp_keeps_a_credential_valid_after_the_certificate_expires() {
    // This is the whole reason time-stamping was added. An Assurance Level 1
    // certificate lasts at most 366 days; without a time-stamp every image the
    // editor ever signed would stop validating on that anniversary.
    let signed = sign_timestamped(&jpeg(200, 150), &request("photo.jpg"));

    let long_after = ValidationOptions {
        validation_time: testpki::after_expiry(),
        ..trusting()
    };
    let report = read(&signed.jpeg, &long_after);

    assert!(
        report.is_valid(),
        "a time-stamped credential must outlive its certificate; failures: {:?}",
        report.active.status.failure
    );
    assert!(codes(&report.active.status.success).contains(&"claimSignature.insideValidity"));
}

#[test]
fn without_a_time_stamp_an_expired_certificate_fails() {
    let signed = sign(&jpeg(200, 150), &request("photo.jpg"));

    let long_after = ValidationOptions {
        validation_time: testpki::after_expiry(),
        ..trusting()
    };
    let report = read(&signed.jpeg, &long_after);

    assert!(!report.is_valid());
    assert!(
        codes(&report.active.status.failure).contains(&"claimSignature.outsideValidity"),
        "got {:?}",
        report.active.status.failure
    );
}

#[test]
fn a_time_stamp_from_an_untrusted_authority_is_ignored_not_fatal() {
    // Section 15.8.2: an unusable time-stamp is informational, and validation
    // falls back to the current time.
    let signed = sign_timestamped(&jpeg(200, 150), &request("photo.jpg"));

    let no_tsa_list = ValidationOptions {
        tsa_trust: TrustStore::empty(),
        ..trusting()
    };
    let report = read(&signed.jpeg, &no_tsa_list);

    assert!(
        report.is_valid(),
        "failures: {:?}",
        report.active.status.failure
    );
    assert!(!report.active.signature.time_stamped);
    assert!(codes(&report.active.status.informational).contains(&"timestamp.untrusted"));
}

#[test]
fn reserving_room_for_a_time_stamp_does_not_change_the_file_when_none_arrives() {
    // The Backend may fail to reach its TSA. The manifest was already sized for
    // one, so the reservation has to become padding without disturbing a single
    // offset.
    let request = request("photo.jpg");
    let source = jpeg(200, 150);
    let with_room = sign_with(&source, &request, testpki::identity(), false);
    let stamped = sign_with(&source, &request, testpki::identity(), true);

    assert_eq!(
        with_room.embedded_len, stamped.embedded_len,
        "the manifest must be the same size whether or not a token arrived"
    );
    assert!(read(&with_room.jpeg, &trusting()).is_valid());
    assert!(read(&stamped.jpeg, &trusting()).is_valid());
}

/* -------------------------------------------------------------------------
Provenance
------------------------------------------------------------------------- */

#[test]
fn a_second_edit_chains_onto_the_first() {
    // The point of provenance: editing an already-credentialed image should
    // carry its history forward rather than starting over.
    let first = sign(&jpeg(320, 240), &{
        let mut request = request("original.jpg");
        request.actions = vec![manifest::Action::new("c2pa.created")
            .source_type("http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture")];
        request
    });

    let parent_report = read(&first.jpeg, &trusting());
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
    let signed = sign(&jpeg(80, 60), &second);
    let report = read(&signed.jpeg, &trusting());

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
    let once = sign(&jpeg(200, 150), &request("first.jpg"));
    let twice = sign(&once.jpeg, &request("second.jpg"));

    let report = read(&twice.jpeg, &trusting());
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

    let signed = sign(&jpeg(200, 150), &request);
    let report = read(&signed.jpeg, &trusting());

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

    let signed = sign(&jpeg(200, 150), &request);
    assert!(
        signed.manifest_len > 64_000,
        "expected a multi-segment manifest, got {} bytes",
        signed.manifest_len
    );

    let report = read(&signed.jpeg, &trusting());
    assert!(
        report.is_valid(),
        "failures: {:?}",
        report.active.status.failure
    );
}

#[test]
fn an_unsigned_jpeg_reports_no_credentials() {
    assert!(c2pa::validate_jpeg(&jpeg(64, 64), &untrusting())
        .unwrap()
        .is_none());
}

#[test]
fn the_exclusion_range_is_exactly_the_manifest() {
    // If the excluded range were even a byte off, the hard binding would either
    // hash part of its own manifest or leave image bytes unprotected.
    let signed = sign(&jpeg(200, 150), &request("photo.jpg"));
    let report = read(&signed.jpeg, &trusting());

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
    let signed = sign(&jpeg(200, 150), &request("photo.jpg"));
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

    let report = read(&tampered, &trusting());
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
    let first = sign(&source, &request("photo.jpg"));
    let second = sign(&source, &request("photo.jpg"));
    assert_eq!(first.jpeg, second.jpeg);
}

#[test]
fn the_signature_leaves_the_tab_but_the_image_does_not() {
    // The one property the whole distributed architecture exists to preserve:
    // what goes to the Backend is a claim, and the picture is not in it.
    let source = jpeg(200, 150);
    let prepared = manifest::prepare(
        &source,
        request("photo.jpg"),
        testpki::identity_without_timestamps(),
    )
    .unwrap();

    // The Sig_structure is dominated by the certificate chain, not by pixels.
    assert!(
        prepared.to_be_signed.len() < source.len() / 4,
        "the bytes sent for signing ({}) should be a fraction of the image ({})",
        prepared.to_be_signed.len(),
        source.len()
    );

    // And no run of image bytes appears inside it.
    let scan = &source[source.len() - 256..];
    assert!(
        !prepared.to_be_signed.windows(scan.len()).any(|w| w == scan),
        "image data must not appear in what is sent for signing"
    );
}

#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    // A Backend that answered with a DER signature, or with a P-384 one, would
    // otherwise produce a manifest whose offsets are silently wrong.
    let prepared = manifest::prepare(
        &jpeg(120, 90),
        request("photo.jpg"),
        testpki::identity_without_timestamps(),
    )
    .unwrap();
    let error = manifest::complete(&prepared, &[0u8; 70], None).unwrap_err();
    assert!(error.contains("70 bytes"), "{error}");
}

#[test]
fn an_oversized_time_stamp_is_reported_so_the_caller_can_reserve_more() {
    let identity = testpki::identity();
    let prepared =
        manifest::prepare(&jpeg(120, 90), request("photo.jpg"), identity.clone()).unwrap();
    let signature = testpki::sign_es256(&prepared.to_be_signed);
    let huge = vec![0u8; prepared.timestamp_budget() + 8192];

    let error = manifest::complete(&prepared, &signature, Some(&huge)).unwrap_err();
    assert!(
        error.contains(imagecore::c2pa::cose::ERR_RESERVATION_TOO_SMALL),
        "{error}"
    );
}
