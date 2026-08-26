//! End-to-end tests for the conformance harness.
//!
//! These run the actual binary the way the Conformance Program will: four
//! inputs in, crJSON out, exit status saying whether the asset validated. What
//! is being checked is not the argument parsing so much as the shape of the
//! document — a crJSON that is subtly wrong is worse than no crJSON, because it
//! looks like evidence.

use std::path::{Path, PathBuf};
use std::process::Command;

use imagecore::c2pa::{self, manifest, testpki, SignRequest};
use serde_json::Value as Json;

const HARNESS: &str = env!("CARGO_BIN_EXE_c2pa-harness");

fn jpeg(width: u32, height: u32) -> Vec<u8> {
    use image::{ImageFormat, Rgb, RgbImage};
    let image = RgbImage::from_fn(width, height, |x, y| {
        Rgb([(x * 7 % 256) as u8, (y * 11 % 256) as u8, 128])
    });
    let mut bytes = Vec::new();
    image
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Jpeg)
        .expect("encoding a JPEG");
    bytes
}

/// A signed asset, produced the way the editor produces one.
fn signed_asset(title: &str, timestamped: bool) -> Vec<u8> {
    let identity = if timestamped {
        testpki::identity()
    } else {
        testpki::identity_without_timestamps()
    };
    let request = SignRequest {
        title: title.to_string(),
        generator: c2pa::generator(),
        now: "2026-08-25T12:00:00Z".to_string(),
        instance_id: "xmp:iid:11111111-2222-3333-4444-555555555555".to_string(),
        manifest_id: "urn:c2pa:AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE".to_string(),
        actions: c2pa::actions_for(&Default::default(), true, (200, 150)),
        parent: Some(manifest::Parent {
            title: "original.jpg".into(),
            format: "image/jpeg".into(),
            instance_id: "xmp:iid:original".into(),
            store: None,
        }),
        thumbnail: None,
    };

    let prepared = manifest::prepare(&jpeg(200, 150), request, identity).unwrap();
    let signature = testpki::sign_es256(&prepared.to_be_signed);
    let token =
        timestamped.then(|| testpki::issue_timestamp(&signature, testpki::validation_time()));
    manifest::complete(&prepared, &signature, token.as_deref())
        .unwrap()
        .jpeg
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("c2pa-harness-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Fixture { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn credentials(&self, name: &str) -> PathBuf {
        testpki::directory().join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Json {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("the harness should print crJSON: {e}\n{}", self.stdout))
    }

    /// The status codes in one of the three result groups of the active
    /// manifest, which is `manifests[0]` in crJSON's reversed order.
    fn status_codes(&self, group: &str) -> Vec<String> {
        self.json()["manifests"][0]["validationResults"][group]
            .as_array()
            .unwrap_or_else(|| panic!("expected a {group} array"))
            .iter()
            .filter_map(|entry| entry["code"].as_str().map(str::to_string))
            .collect()
    }
}

fn harness(args: &[&std::ffi::OsStr]) -> Run {
    let output = Command::new(HARNESS)
        .args(args)
        .output()
        .expect("running the harness");
    Run {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// The four inputs the Conformance Program specifies, as command-line flags.
fn conformance_args(asset: &Path, fixture: &Fixture) -> Vec<std::ffi::OsString> {
    vec![
        "validate".into(),
        "--asset".into(),
        asset.to_path_buf().into(),
        "--trust-list".into(),
        fixture.credentials("c2pa-test-trust-list.pem").into(),
        "--tsa-trust-list".into(),
        fixture.credentials("c2pa-test-tsa-trust-list.pem").into(),
        "--validation-time".into(),
        c2pa::clock::to_rfc3339(testpki::validation_time()).into(),
    ]
}

fn run_conformance(asset: &Path, fixture: &Fixture) -> Run {
    let owned = conformance_args(asset, fixture);
    let refs: Vec<&std::ffi::OsStr> = owned.iter().map(|s| s.as_os_str()).collect();
    harness(&refs)
}

#[test]
fn a_valid_asset_produces_crjson_and_exits_zero() {
    let fixture = Fixture::new("valid");
    let asset = fixture.write("signed.jpg", &signed_asset("holiday.jpg", true));
    let run = run_conformance(&asset, &fixture);

    assert_eq!(run.status, 0, "stderr: {}", run.stderr);
    let document = run.json();

    // Section 3.1: the three required top-level properties.
    assert!(document.get("@context").is_some());
    assert!(document.get("jsonGenerator").is_some());
    let manifests = document["manifests"].as_array().expect("manifests array");
    assert_eq!(manifests.len(), 1);

    // Section 3.3: name and a SemVer version.
    let generator = &document["jsonGenerator"];
    assert!(generator["name"].as_str().is_some_and(|n| !n.is_empty()));
    assert!(generator["version"]
        .as_str()
        .is_some_and(|v| v.split('.').count() == 3));

    let manifest = &manifests[0];
    assert!(manifest["label"].as_str().unwrap().starts_with("urn:c2pa:"));
    assert!(manifest.get("claim.v2").is_some(), "a v2 claim is written");
    assert!(manifest.get("assertions").is_some());
    assert!(manifest.get("signature").is_some());
    assert!(manifest.get("validationResults").is_some());
}

#[test]
fn the_claim_carries_both_assertion_lists_even_when_empty() {
    // Section 3.5.1 requires them present, and a validator comparing two
    // implementations will notice their absence before anything else.
    let fixture = Fixture::new("lists");
    let asset = fixture.write("signed.jpg", &signed_asset("photo.jpg", false));
    let claim = run_conformance(&asset, &fixture).json()["manifests"][0]["claim.v2"].clone();

    assert_eq!(claim["gathered_assertions"], serde_json::json!([]));
    assert_eq!(claim["redacted_assertions"], serde_json::json!([]));
    assert!(claim["created_assertions"].as_array().unwrap().len() >= 2);
}

#[test]
fn byte_strings_are_base64_with_the_b64_prefix() {
    let fixture = Fixture::new("b64");
    let asset = fixture.write("signed.jpg", &signed_asset("photo.jpg", false));
    let document = run_conformance(&asset, &fixture).json();

    let hash = document["manifests"][0]["assertions"]["c2pa.hash.data"]["hash"]
        .as_str()
        .expect("the data hash should be present");
    assert!(hash.starts_with("b64'"), "got {hash}");
    // 32 bytes of SHA-256 is 44 Base64 characters, plus the four-character
    // prefix.
    assert_eq!(hash.len(), 4 + 44, "got {hash}");
}

#[test]
fn the_validation_results_carry_the_time_they_were_produced_at() {
    let fixture = Fixture::new("time");
    let asset = fixture.write("signed.jpg", &signed_asset("photo.jpg", false));
    let document = run_conformance(&asset, &fixture).json();

    let results = &document["manifests"][0]["validationResults"];
    let at = results["validationTime"].as_str().expect("validationTime");
    assert_eq!(at, c2pa::clock::to_rfc3339(testpki::validation_time()));
    assert!(results["success"].is_array());
    assert!(results["informational"].is_array());
    assert!(results["failure"].is_array());
}

#[test]
fn a_trusted_signer_is_reported_with_its_certificate_details() {
    let fixture = Fixture::new("signer");
    let asset = fixture.write("signed.jpg", &signed_asset("photo.jpg", true));
    let run = run_conformance(&asset, &fixture);
    let document = run.json();

    let signature = &document["manifests"][0]["signature"];
    assert_eq!(signature["algorithm"], "ES256");

    // Section 3.7's required certificateInfo fields.
    let info = &signature["certificateInfo"];
    assert!(info["serialNumber"].as_str().is_some());
    assert_eq!(info["subject"]["CN"], "A10city Image Editor");
    assert_eq!(info["subject"]["O"], "A10city Labs");
    assert!(info["issuer"]["CN"]
        .as_str()
        .unwrap()
        .contains("Claim Signing CA"));
    assert!(info["validity"]["notBefore"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    assert!(info["validity"]["notAfter"]
        .as_str()
        .unwrap()
        .ends_with('Z'));

    // The conformance facts, from the C2PA Certificate Policy extensions.
    assert_eq!(info["extras:c2pa"]["assuranceLevel"], 1);
    assert_eq!(
        info["extras:c2pa"]["cplRecordId"],
        "00000000-0000-0000-0000-000000000000"
    );

    // And the time-stamp, with the authority's own certificate.
    let timestamp = &signature["timestampInfo"];
    assert!(timestamp["timestamp"].as_str().unwrap().ends_with('Z'));
    assert!(timestamp["certificateInfo"]["subject"]["CN"]
        .as_str()
        .unwrap()
        .contains("Timestamp Authority"));

    let codes = run.status_codes("success");
    assert!(
        codes.iter().any(|c| c == "signingCredential.trusted"),
        "{codes:?}"
    );
    assert!(
        codes.iter().any(|c| c == "timeStamp.validated"),
        "{codes:?}"
    );
}

#[test]
fn a_tampered_asset_exits_one_and_says_which_check_caught_it() {
    let fixture = Fixture::new("tampered");
    let mut bytes = signed_asset("photo.jpg", false);
    let at = bytes.len() - 40;
    bytes[at] ^= 0xFF;
    let asset = fixture.write("tampered.jpg", &bytes);

    let run = run_conformance(&asset, &fixture);
    assert_eq!(run.status, 1, "a tampered asset must not report as valid");

    let failures = run.status_codes("failure");
    assert!(
        failures
            .iter()
            .any(|code| code == "assertion.dataHash.mismatch"),
        "{failures:?}"
    );
}

#[test]
fn an_untrusted_signer_is_a_failure_when_a_trust_list_was_supplied() {
    let fixture = Fixture::new("untrusted");
    let asset = fixture.write("signed.jpg", &signed_asset("photo.jpg", false));

    // The TSA list is a valid trust list that simply lacks this signer's root.
    let run = harness(&[
        "validate".as_ref(),
        "--asset".as_ref(),
        asset.as_os_str(),
        "--trust-list".as_ref(),
        fixture
            .credentials("c2pa-test-tsa-trust-list.pem")
            .as_os_str(),
        "--validation-time".as_ref(),
        c2pa::clock::to_rfc3339(testpki::validation_time()).as_ref(),
    ]);

    assert_eq!(run.status, 1);
    let failures = run.status_codes("failure");
    assert!(
        failures
            .iter()
            .any(|code| code == "signingCredential.untrusted"),
        "{failures:?}"
    );
}

#[test]
fn the_validation_time_changes_the_answer() {
    // The Program supplies a validation time with each asset precisely because
    // it decides expiry. A harness that ignored it would pass today and fail
    // in a year.
    let fixture = Fixture::new("expiry");
    let asset = fixture.write("signed.jpg", &signed_asset("photo.jpg", false));

    let expired = harness(&[
        "validate".as_ref(),
        "--asset".as_ref(),
        asset.as_os_str(),
        "--trust-list".as_ref(),
        fixture.credentials("c2pa-test-trust-list.pem").as_os_str(),
        "--validation-time".as_ref(),
        c2pa::clock::to_rfc3339(testpki::after_expiry()).as_ref(),
    ]);
    assert_eq!(expired.status, 1);

    let failures = expired.status_codes("failure");
    assert!(
        failures
            .iter()
            .any(|code| code == "claimSignature.outsideValidity"),
        "{failures:?}"
    );
}

#[test]
fn a_missing_validation_time_is_refused_rather_than_guessed() {
    let fixture = Fixture::new("no-time");
    let asset = fixture.write("signed.jpg", &signed_asset("photo.jpg", false));
    let run = harness(&["validate".as_ref(), "--asset".as_ref(), asset.as_os_str()]);

    assert_eq!(run.status, 2, "a harness that guesses the time is useless");
    assert!(run.stderr.contains("--validation-time"), "{}", run.stderr);
}

#[test]
fn batch_mode_writes_one_document_per_asset() {
    let fixture = Fixture::new("batch");
    let assets = fixture.dir.join("assets");
    let out = fixture.dir.join("out");
    std::fs::create_dir_all(&assets).unwrap();
    std::fs::write(assets.join("one.jpg"), signed_asset("one.jpg", false)).unwrap();
    std::fs::write(assets.join("two.jpg"), signed_asset("two.jpg", true)).unwrap();
    // A file the batch should ignore rather than choke on.
    std::fs::write(assets.join("notes.txt"), b"not an asset").unwrap();

    let run = harness(&[
        "batch".as_ref(),
        "--asset-dir".as_ref(),
        assets.as_os_str(),
        "--output-dir".as_ref(),
        out.as_os_str(),
        "--trust-list".as_ref(),
        fixture.credentials("c2pa-test-trust-list.pem").as_os_str(),
        "--tsa-trust-list".as_ref(),
        fixture
            .credentials("c2pa-test-tsa-trust-list.pem")
            .as_os_str(),
        "--validation-time".as_ref(),
        c2pa::clock::to_rfc3339(testpki::validation_time()).as_ref(),
    ]);

    assert_eq!(run.status, 0, "stderr: {}", run.stderr);
    for name in ["one.crjson", "two.crjson"] {
        let path = out.join(name);
        assert!(path.exists(), "{name} should have been written");
        let document: Json =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(document["manifests"].as_array().unwrap().len() == 1);
    }
}

#[test]
fn an_asset_with_no_credentials_is_an_error_not_an_empty_document() {
    let fixture = Fixture::new("bare");
    let asset = fixture.write("bare.jpg", &jpeg(64, 64));
    let run = run_conformance(&asset, &fixture);

    assert_eq!(run.status, 2);
    assert!(
        run.stderr.contains("no Content Credentials"),
        "{}",
        run.stderr
    );
}
