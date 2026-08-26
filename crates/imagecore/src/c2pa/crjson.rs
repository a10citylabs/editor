//! The crJSON serialisation of a manifest store and its validation results.
//!
//! crJSON is a JSON-LD view over a C2PA manifest store, defined by the *Content
//! Credentials JSON (crJSON) File Format Specification*. It is not a
//! cryptographic artefact and cannot be validated on its own; it exists so that
//! two implementations can be compared field by field.
//!
//! That comparison is the reason this module exists. The Conformance Program
//! requires any applicant whose product validates manifests to run a test
//! harness over assets the Program supplies — with a test C2PA Trust List, a
//! test TSA Trust List and a fixed validation time — and hand back crJSON. So
//! this is the product's validator speaking the Program's language, not a
//! separate reporting path that could disagree with what the browser shows.
//! `crates/c2pa-harness` is the command-line front end; the browser can export
//! the same document.
//!
//! # The bits that are easy to get wrong
//!
//! - **Manifest order is reversed.** The store holds the active manifest last;
//!   crJSON puts it first.
//! - **Byte strings are Base64 with a `b64'` prefix**, not bare Base64 and not
//!   hex.
//! - **`gathered_assertions` and `redacted_assertions` are always present**,
//!   as empty arrays when the claim omits them.
//! - **CBOR tag 0 unwraps** to the plain date-time string inside it.
//! - **Non-text map keys become strings**, because JSON has no other kind.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Map, Value as Json};

use super::cbor::Value;
use super::clock;
use super::manifest::{ManifestReport, StatusCodes, ValidationReport};
use super::x509::{self, Certificate};

/// The tool identification crJSON requires, in SemVer 2.0 form.
fn json_generator() -> Json {
    json!({
        "name": "A10city Image Editor conformance harness",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// Render a validation report as a crJSON document.
pub fn to_crjson(report: &ValidationReport) -> Json {
    // Section 3.4: reverse store order, so the active manifest is first.
    let manifests: Vec<Json> = report
        .chain
        .iter()
        .rev()
        .map(|manifest| to_manifest(manifest, &report.validation_time))
        .collect();

    json!({
        "@context": {
            "@vocab": "https://c2pa.org/crjson/",
            "extras": "https://c2pa.org/crjson/extras/",
        },
        "jsonGenerator": json_generator(),
        "manifests": manifests,
    })
}

fn to_manifest(report: &ManifestReport, validation_time: &str) -> Json {
    let mut manifest = Map::new();
    manifest.insert("label".into(), json!(report.label));

    // The claim keeps the label of its own box, so a v1 claim reads as `claim`
    // and a v2 claim as `claim.v2`.
    let claim_key = if report.raw.claim_label == "c2pa.claim" {
        "claim"
    } else {
        "claim.v2"
    };
    let claim = report
        .raw
        .claim
        .as_ref()
        .map(to_json)
        .unwrap_or_else(|| json!({}));
    manifest.insert(claim_key.into(), with_empty_assertion_arrays(claim));

    let mut assertions = Map::new();
    for (label, value) in &report.raw.assertions {
        // Section 3.6.1: an assertion that could not be decoded is still
        // listed, with an empty object as its value.
        assertions.insert(
            label.clone(),
            value.as_ref().map(to_json).unwrap_or_else(|| json!({})),
        );
    }
    manifest.insert("assertions".into(), Json::Object(assertions));
    manifest.insert("signature".into(), to_signature(report));
    manifest.insert(
        "validationResults".into(),
        to_validation_results(&report.status, validation_time),
    );

    Json::Object(manifest)
}

/// Section 3.5.1: both assertion lists are always present, empty if absent.
fn with_empty_assertion_arrays(claim: Json) -> Json {
    let Json::Object(mut map) = claim else {
        return claim;
    };
    for key in ["gathered_assertions", "redacted_assertions"] {
        map.entry(key.to_string()).or_insert_with(|| json!([]));
    }
    Json::Object(map)
}

fn to_signature(report: &ManifestReport) -> Json {
    let Some(leaf) = report
        .raw
        .chain
        .first()
        .and_then(|der| x509::parse_certificate(der).ok())
    else {
        // Section 3.7: an empty object when there is no signature information.
        return json!({});
    };

    let mut signature = Map::new();
    signature.insert("algorithm".into(), json!(report.signature.algorithm));
    signature.insert("certificateInfo".into(), to_certificate_info(&leaf));

    if report.signature.time_stamped {
        let mut info = Map::new();
        info.insert("timestamp".into(), json!(report.signature.time_stamp));
        if let Some(tsa) = report
            .raw
            .timestamp_token
            .as_ref()
            .and_then(|token| super::timestamp::parse(token).ok())
        {
            info.insert("certificateInfo".into(), to_certificate_info(&tsa.signer));
        }
        signature.insert("timestampInfo".into(), Json::Object(info));
    }

    Json::Object(signature)
}

fn to_certificate_info(certificate: &Certificate) -> Json {
    let dn = |attributes: &[(String, String)]| -> Json {
        let mut map = Map::new();
        for (label, value) in attributes {
            map.insert(label.clone(), json!(value));
        }
        Json::Object(map)
    };

    // The serial is a hex string here rather than the decimal one the crJSON
    // example shows: a twenty-octet serial has no exact decimal form in JSON's
    // number type, and the specification's own note allows implementations to
    // add and shape fields sensibly.
    let mut info = Map::new();
    info.insert("serialNumber".into(), json!(certificate.serial));
    info.insert("subject".into(), dn(&certificate.subject_attributes));
    info.insert("issuer".into(), dn(&certificate.issuer_attributes));
    info.insert(
        "validity".into(),
        json!({
            "notBefore": certificate.not_before,
            "notAfter": certificate.not_after,
        }),
    );

    // The extensions the C2PA Certificate Policy adds are the whole point of a
    // conformance-grade report, so they go in even though crJSON does not name
    // them. Section 3.7 says implementations may include more.
    let mut extras = Map::new();
    if let Some(level) = certificate.c2pa_assurance_level {
        extras.insert("assuranceLevel".into(), json!(level));
    }
    if let Some(record) = &certificate.c2pa_cpl_record_id {
        extras.insert("cplRecordId".into(), json!(record));
    }
    if !certificate.extended_key_usage.is_empty() {
        extras.insert(
            "extendedKeyUsage".into(),
            json!(certificate.extended_key_usage),
        );
    }
    if !extras.is_empty() {
        info.insert("extras:c2pa".into(), Json::Object(extras));
    }

    Json::Object(info)
}

fn to_validation_results(status: &StatusCodes, validation_time: &str) -> Json {
    let list = |entries: &[super::manifest::Status]| -> Json {
        Json::Array(
            entries
                .iter()
                .map(|entry| {
                    json!({
                        "code": entry.code,
                        "explanation": entry.explanation,
                    })
                })
                .collect(),
        )
    };

    json!({
        "success": list(&status.success),
        "informational": list(&status.informational),
        "failure": list(&status.failure),
        "validationTime": validation_time,
    })
}

/// Table 1 of the crJSON specification: CBOR to JSON-LD.
pub fn to_json(value: &Value) -> Json {
    match value {
        Value::Uint(n) => json!(n),
        Value::Uint32(n) => json!(n),
        Value::NegInt(n) => json!(n),
        Value::Bytes(bytes) => json!(format!("b64'{}", BASE64.encode(bytes))),
        Value::Text(text) => json!(text),
        Value::Array(items) => Json::Array(items.iter().map(to_json).collect()),
        Value::Map(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                map.insert(key_to_string(key), to_json(value));
            }
            Json::Object(map)
        }
        Value::Bool(b) => json!(b),
        Value::Null => Json::Null,
        // Tag 0 is a date-time; the specification says to copy the text out of
        // it. Any other tag is transparent for these purposes.
        Value::Tag(_, inner) => to_json(inner),
    }
}

/// JSON object keys are strings, so a CBOR key of any other type is rendered.
fn key_to_string(key: &Value) -> String {
    match key {
        Value::Text(text) => text.clone(),
        Value::Uint(n) => n.to_string(),
        Value::Uint32(n) => n.to_string(),
        Value::NegInt(n) => n.to_string(),
        Value::Bytes(bytes) => format!("b64'{}", BASE64.encode(bytes)),
        other => format!("{other:?}"),
    }
}

/// Parse the validation time back out of a crJSON document, for tests and for
/// tools that round-trip one.
pub fn validation_time_of(document: &Json) -> Option<i64> {
    document
        .get("manifests")?
        .as_array()?
        .first()?
        .get("validationResults")?
        .get("validationTime")?
        .as_str()
        .and_then(clock::parse_rfc3339)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_strings_carry_the_b64_prefix() {
        let value = Value::Map(vec![(Value::text("hash"), Value::bytes(vec![1, 2, 3]))]);
        let json = to_json(&value);
        assert_eq!(json["hash"], json!("b64'AQID"));
    }

    #[test]
    fn a_tagged_date_time_unwraps_to_its_text() {
        let value = Value::datetime("2026-08-26T12:00:00Z");
        assert_eq!(to_json(&value), json!("2026-08-26T12:00:00Z"));
    }

    #[test]
    fn negative_integers_stay_negative() {
        assert_eq!(to_json(&Value::NegInt(-7)), json!(-7));
        assert_eq!(to_json(&Value::Uint(7)), json!(7));
    }

    #[test]
    fn non_text_keys_become_strings() {
        let value = Value::Map(vec![(Value::Uint(1), Value::text("alg"))]);
        assert_eq!(to_json(&value), json!({"1": "alg"}));
    }

    #[test]
    fn a_claim_always_carries_both_assertion_lists() {
        let claim = json!({"instanceID": "xmp:iid:1"});
        let filled = with_empty_assertion_arrays(claim);
        assert_eq!(filled["gathered_assertions"], json!([]));
        assert_eq!(filled["redacted_assertions"], json!([]));
    }

    #[test]
    fn an_existing_assertion_list_is_left_alone() {
        let claim = json!({"gathered_assertions": [{"url": "x"}]});
        let filled = with_empty_assertion_arrays(claim);
        assert_eq!(filled["gathered_assertions"].as_array().unwrap().len(), 1);
    }
}
