//! Sample assets for the C2PA Conformance Program.
//!
//! The Program asks a Generator Product applicant for "sample output media
//! files of every asserted generate and validate media type", with their
//! crJSON alongside. This writes the media files; `c2pa-harness` writes the
//! crJSON, and `conformance/scripts/generate-evidence.sh` runs both.
//!
//! Marked `#[ignore]` because it writes into the repository rather than
//! asserting anything, so an ordinary `cargo test` does not touch the working
//! tree. Run it with:
//!
//! ```text
//!   cargo test -p imagecore --test evidence -- --ignored --nocapture
//! ```
//!
//! Each sample is chosen to exercise a different part of what an assessor will
//! look at, rather than to be a set of near-identical files.

use std::path::PathBuf;

use image::{ImageFormat, Rgb, RgbImage};
use imagecore::c2pa::{self, manifest, testpki, SignRequest};
use imagecore::pipeline::{AdjustSpec, Crop, Pipeline, Resize};

fn output_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/evidence/assets");
    std::fs::create_dir_all(&dir).expect("creating the evidence directory");
    dir
}

fn jpeg(width: u32, height: u32) -> Vec<u8> {
    let image = RgbImage::from_fn(width, height, |x, y| {
        Rgb([
            (x * 5 % 256) as u8,
            (y * 9 % 256) as u8,
            ((x ^ y) % 256) as u8,
        ])
    });
    let mut bytes = Vec::new();
    image
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Jpeg)
        .expect("encoding a JPEG");
    bytes
}

/// Everything non-deterministic is pinned, so re-running produces byte-identical
/// evidence and a reviewer can diff two runs.
fn request(title: &str, manifest_id: &str) -> SignRequest {
    SignRequest {
        title: title.to_string(),
        generator: c2pa::generator(),
        now: "2026-08-25T12:00:00Z".to_string(),
        instance_id: format!("xmp:iid:{manifest_id}"),
        manifest_id: format!("urn:c2pa:{manifest_id}"),
        actions: Vec::new(),
        parent: Some(manifest::Parent {
            title: "camera-original.jpg".into(),
            format: "image/jpeg".into(),
            instance_id: "xmp:iid:00000000-0000-4000-8000-000000000000".into(),
            store: None,
        }),
        thumbnail: None,
    }
}

fn sign(source: &[u8], request: SignRequest, timestamped: bool) -> Vec<u8> {
    let identity = if timestamped {
        testpki::identity()
    } else {
        testpki::identity_without_timestamps()
    };
    let prepared = manifest::prepare(source, request, identity).expect("preparing");
    let signature = testpki::sign_es256(&prepared.to_be_signed);
    let token =
        timestamped.then(|| testpki::issue_timestamp(&signature, testpki::validation_time()));
    manifest::complete(&prepared, &signature, token.as_deref())
        .expect("completing")
        .jpeg
}

fn write(name: &str, bytes: &[u8]) {
    let path = output_dir().join(name);
    std::fs::write(&path, bytes).expect("writing the sample");
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

#[test]
#[ignore = "writes evidence into the repository; run with --ignored"]
fn write_conformance_samples() {
    let source = jpeg(640, 480);

    // 1. The ordinary case: an edited photograph, time-stamped. This is what
    //    the product produces in normal operation and what most of the
    //    assessment will be about.
    let mut edited = request(
        "edited-photograph.jpg",
        "11111111-1111-4111-8111-111111111111",
    );
    edited.actions = c2pa::actions_for(
        &Pipeline {
            crop: Some(Crop {
                x: 20,
                y: 30,
                width: 400,
                height: 300,
            }),
            quarter_turns: 1,
            resize: Some(Resize {
                width: 200,
                height: 150,
                filter: "lanczos3".into(),
            }),
            adjust: AdjustSpec {
                brightness: 0.1,
                saturation: -0.2,
                ..Default::default()
            },
            ..Default::default()
        },
        true,
        (200, 150),
    );
    edited.thumbnail = Some(jpeg(160, 120));
    write("01-edited-timestamped.jpg", &sign(&source, edited, true));

    // 2. The same edit with no time-stamp, so an assessor can see what the
    //    validator says about long-term validity when the TSA was unreachable.
    let mut untimestamped = request(
        "edited-photograph.jpg",
        "22222222-2222-4222-8222-222222222222",
    );
    untimestamped.actions = c2pa::actions_for(&Pipeline::default(), true, (640, 480));
    write("02-no-timestamp.jpg", &sign(&source, untimestamped, false));

    // 3. A file opened and saved with nothing changed. The actions assertion
    //    has to say so honestly rather than implying an edit.
    let mut untouched = request("unchanged.jpg", "33333333-3333-4333-8333-333333333333");
    untouched.actions = c2pa::actions_for(&Pipeline::default(), true, (640, 480));
    write("03-opened-unchanged.jpg", &sign(&source, untouched, true));

    // 4. Two generations, so the ingredient and the inherited manifest are both
    //    in the evidence. This is the sample that shows the product ingests
    //    manifests, which the Program asks about separately.
    let first = sign(
        &source,
        {
            let mut r = request("generation-one.jpg", "44444444-4444-4444-8444-444444444444");
            r.actions = c2pa::actions_for(&Pipeline::default(), true, (640, 480));
            r
        },
        true,
    );
    let parent = c2pa::validate_jpeg(
        &first,
        &c2pa::ValidationOptions::untrusted(testpki::validation_time()),
    )
    .expect("reading generation one")
    .expect("generation one should carry a manifest");

    let mut second = request("generation-two.jpg", "55555555-5555-4555-8555-555555555555");
    second.actions = c2pa::actions_for(
        &Pipeline {
            adjust: AdjustSpec {
                grayscale: true,
                ..Default::default()
            },
            ..Default::default()
        },
        true,
        (320, 240),
    );
    second.parent = Some(manifest::Parent {
        title: "generation-one.jpg".into(),
        format: "image/jpeg".into(),
        instance_id: parent.active.instance_id.clone(),
        store: Some(manifest::ParentStore {
            bytes: parent.store.clone(),
            active_manifest: parent.active.label.clone(),
            status: parent.active.status.clone(),
        }),
    });
    write(
        "04-two-generations.jpg",
        &sign(&jpeg(320, 240), second, true),
    );

    // 5. A deliberately broken one. The Program's own library includes assets
    //    that must fail, and evidence that the validator reports a failure is
    //    as important as evidence that it reports a success.
    let mut tampered = sign(
        &source,
        {
            let mut r = request("tampered.jpg", "66666666-6666-4666-8666-666666666666");
            r.actions = c2pa::actions_for(&Pipeline::default(), true, (640, 480));
            r
        },
        true,
    );
    let at = tampered.len() - 64;
    tampered[at] ^= 0xFF;
    write("05-tampered-pixels.jpg", &tampered);
}
