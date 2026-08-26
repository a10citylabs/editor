//! Content Credentials: a browser-side C2PA claim generator.
//!
//! This writes and reads C2PA 2.2 manifests for JPEG files, entirely inside the
//! tab. Nothing is uploaded, and no reference implementation is linked in — the
//! JUMBF containers, deterministic CBOR, COSE signatures and JPEG embedding are
//! all built from the specification. The submodules are, in dependency order:
//!
//! | Module | Specification |
//! |---|---|
//! | [`cbor`] | RFC 8949, incl. the deterministic encoding of clause 4.2.1 |
//! | [`jumbf`] | ISO/IEC 19566-5 boxes; C2PA §11.1 labels and UUIDs |
//! | [`jpegxt`] | C2PA §A.3.1 `APP11` embedding; §18.5.3 exclusion rules |
//! | [`x509`] | Enough DER to read a certificate (RFC 5280) |
//! | [`cose`] | RFC 8152 `COSE_Sign1`, RFC 9360 `x5chain`; C2PA §13.2 |
//! | [`signer`] | The build's key material |
//! | [`manifest`] | C2PA §10 claims, §18 assertions, §15 validation |
//!
//! # Why JPEG only
//!
//! The hard binding this generator writes is `c2pa.hash.data`, which commits to
//! a byte range of the finished file. That means the manifest has to be
//! embeddable at a known offset in a way the format tolerates, and the exclusion
//! rules have to be written per format (§18.5.3 for JPEG, §18.5.4 for PNG, and
//! so on). JPEG's `APP11` segments are the case the specification treats in the
//! most detail, and they are what the overwhelming majority of C2PA tooling
//! reads today.
//!
//! Doing this properly for one format teaches more than doing it loosely for
//! six. Every other output format the editor supports keeps working exactly as
//! it did — it just does not get a credential, and the interface says so rather
//! than leaving the option greyed out with no explanation.
//!
//! # What this proves and what it does not
//!
//! A credential written here genuinely establishes that the pixels have not
//! changed since signing, and genuinely records what the editor did to them. It
//! does not establish *who* signed: the key ships inside the page, so anyone can
//! produce a manifest bearing this signer's name. See `signing/README.md`.
//!
//! Two things a production claim generator would add are missing for reasons
//! that are about the environment rather than effort: an RFC 3161 time-stamp
//! (§10.3.2.5) and a stapled OCSP response (§10.3.2.6). Both need a network
//! round-trip to a third party while signing, which an app whose whole premise
//! is that nothing leaves the tab cannot make. Their absence is reported to the
//! user rather than hidden.

pub mod cbor;
pub mod cose;
pub mod jpegxt;
pub mod jumbf;
pub mod manifest;
pub mod signer;
pub mod x509;

use cbor::Value;
use manifest::{Action, GeneratorInfo};

pub use manifest::{
    read_jpeg, sign_jpeg, IngredientReport, ManifestReport, Parent, ParentStore, SignRequest,
    Signed, ValidationReport,
};

use crate::pipeline::Pipeline;

/// The IPTC digital source type for an image a human captured or edited, as
/// opposed to one a model generated. Recording it is how a viewer can tell the
/// difference at a glance.
///
/// <https://cv.iptc.org/newscodes/digitalsourcetype/>
const SOURCE_TYPE_DIGITAL_CAPTURE: &str =
    "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";

/// Whether a manifest can be written for this output format.
///
/// See the module docs for why this is JPEG alone.
pub fn supports_format(format: &str) -> bool {
    matches!(format.to_ascii_lowercase().as_str(), "jpeg" | "jpg")
}

/// How this build identifies itself in claims.
pub fn generator() -> GeneratorInfo {
    GeneratorInfo {
        name: "A10city Image Editor".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Translate an edit pipeline into the actions that describe it.
///
/// This is the part that makes a credential *mean* something. A manifest whose
/// actions say `c2pa.edited` and nothing else is technically valid and tells a
/// reader nothing; the point of the actions assertion is that someone looking
/// at the image afterwards can see what was done to it. So each operation the
/// pipeline actually performed gets its own action, with the predefined name
/// that fits it and parameters carrying the specifics.
///
/// The order mirrors the order the pipeline applies them in, which is also the
/// order they happened in as far as the output is concerned.
///
/// `opened` prepends the `c2pa.opened` action that section 18.10.2 requires
/// when an existing asset was opened for editing.
pub fn actions_for(pipeline: &Pipeline, opened: bool, output: (u32, u32)) -> Vec<Action> {
    let mut actions = Vec::new();

    if opened {
        // Must be the first element, and must point at a parentOf ingredient.
        // `manifest` wires up the ingredient reference itself.
        actions.push(Action::new("c2pa.opened"));
    } else {
        actions.push(Action::new("c2pa.created").param(
            "digitalSourceType",
            Value::text(SOURCE_TYPE_DIGITAL_CAPTURE),
        ));
    }

    if pipeline.flip_h || pipeline.flip_v || !pipeline.quarter_turns.is_multiple_of(4) {
        let mut described = Vec::new();
        if !pipeline.quarter_turns.is_multiple_of(4) {
            described.push(format!("rotated {}°", (pipeline.quarter_turns % 4) * 90));
        }
        if pipeline.flip_h {
            described.push("flipped horizontally".to_string());
        }
        if pipeline.flip_v {
            described.push("flipped vertically".to_string());
        }
        actions.push(
            Action::new("c2pa.orientation")
                .describe(described.join(", "))
                .param(
                    "com.a10city.quarterTurns",
                    Value::Uint(u64::from(pipeline.quarter_turns % 4)),
                )
                .param("com.a10city.flipHorizontal", Value::Bool(pipeline.flip_h))
                .param("com.a10city.flipVertical", Value::Bool(pipeline.flip_v)),
        );
    }

    if pipeline.angle.abs() > f32::EPSILON {
        // A free rotation is a resample, not a lossless turn, so it is a
        // distinct action from c2pa.orientation above.
        actions.push(
            Action::new("c2pa.orientation")
                .describe(format!("straightened by {:.1}°", pipeline.angle))
                .param(
                    "com.a10city.angleDegrees",
                    Value::text(format!("{:.2}", pipeline.angle)),
                ),
        );
    }

    if let Some(crop) = &pipeline.crop {
        actions.push(
            Action::new("c2pa.cropped")
                .describe(format!(
                    "cropped to {}x{} at ({}, {})",
                    crop.width, crop.height, crop.x, crop.y
                ))
                .param("com.a10city.x", Value::Uint(u64::from(crop.x)))
                .param("com.a10city.y", Value::Uint(u64::from(crop.y)))
                .param("com.a10city.width", Value::Uint(u64::from(crop.width)))
                .param("com.a10city.height", Value::Uint(u64::from(crop.height))),
        );
    }

    if pipeline.resize.is_some() {
        actions.push(
            Action::new("c2pa.resized")
                .describe(format!("resized to {}x{}", output.0, output.1))
                .param("com.a10city.width", Value::Uint(u64::from(output.0)))
                .param("com.a10city.height", Value::Uint(u64::from(output.1))),
        );
    }

    let adjust = &pipeline.adjust;

    // Tone and colour. `c2pa.adjustedColor` is the predefined name for exactly
    // this - "changes to tone, saturation, etc."
    let mut colour = Vec::new();
    if adjust.brightness.abs() > f32::EPSILON {
        colour.push(format!("brightness {:+.2}", adjust.brightness));
    }
    if adjust.contrast.abs() > f32::EPSILON {
        colour.push(format!("contrast {:+.2}", adjust.contrast));
    }
    if adjust.saturation.abs() > f32::EPSILON {
        colour.push(format!("saturation {:+.2}", adjust.saturation));
    }
    if adjust.grayscale {
        colour.push("converted to grayscale".to_string());
    }
    if adjust.invert {
        colour.push("inverted".to_string());
    }
    if !colour.is_empty() {
        actions.push(Action::new("c2pa.adjustedColor").describe(colour.join(", ")));
    }

    // Sharpening is an enhancement in C2PA's vocabulary - a non-editorial
    // transformation - while a blur changes appearance and is a filter.
    if adjust.sharpen > f32::EPSILON {
        actions.push(
            Action::new("c2pa.enhanced")
                .describe(format!("unsharp mask, amount {:.2}", adjust.sharpen)),
        );
    }
    if adjust.blur > f32::EPSILON {
        actions.push(
            Action::new("c2pa.filtered")
                .describe(format!("Gaussian blur, sigma {:.2}", adjust.blur)),
        );
    }

    actions
}

/// Whether a pipeline changes any pixels.
///
/// A file that was opened and saved with no edits still gets a credential, but
/// its actions should say so honestly rather than implying an edit happened.
pub fn is_untouched(pipeline: &Pipeline) -> bool {
    let adjust = &pipeline.adjust;
    pipeline.crop.is_none()
        && !pipeline.flip_h
        && !pipeline.flip_v
        && pipeline.quarter_turns.is_multiple_of(4)
        && pipeline.angle.abs() <= f32::EPSILON
        && pipeline.resize.is_none()
        && adjust.brightness.abs() <= f32::EPSILON
        && adjust.contrast.abs() <= f32::EPSILON
        && adjust.saturation.abs() <= f32::EPSILON
        && !adjust.grayscale
        && !adjust.invert
        && adjust.blur <= f32::EPSILON
        && adjust.sharpen <= f32::EPSILON
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{Crop, Resize};

    fn empty() -> Pipeline {
        Pipeline::default()
    }

    #[test]
    fn only_jpeg_gets_credentials() {
        assert!(supports_format("jpeg"));
        assert!(supports_format("jpg"));
        assert!(supports_format("JPEG"));
        for other in ["png", "webp", "gif", "tiff", "bmp", "qoi", ""] {
            assert!(!supports_format(other), "{other} should not be supported");
        }
    }

    #[test]
    fn an_opened_file_starts_with_c2pa_opened() {
        // Section 18.10.2 requires this as the first element, and section
        // 15.10.3.2.2 rejects the claim if it does not resolve to a parentOf
        // ingredient.
        let actions = actions_for(&empty(), true, (100, 100));
        assert_eq!(actions[0].action, "c2pa.opened");
    }

    #[test]
    fn a_new_file_starts_with_c2pa_created() {
        let actions = actions_for(&empty(), false, (100, 100));
        assert_eq!(actions[0].action, "c2pa.created");
        assert!(actions[0]
            .parameters
            .iter()
            .any(|(key, _)| key == "digitalSourceType"));
    }

    #[test]
    fn an_unedited_pipeline_records_no_edit_actions() {
        let actions = actions_for(&empty(), true, (100, 100));
        assert_eq!(actions.len(), 1, "opening alone is not an edit");
        assert!(is_untouched(&empty()));
    }

    #[test]
    fn each_operation_gets_its_own_action() {
        let pipeline = Pipeline {
            crop: Some(Crop {
                x: 10,
                y: 20,
                width: 300,
                height: 400,
            }),
            quarter_turns: 1,
            flip_h: true,
            angle: -2.5,
            resize: Some(Resize {
                width: 150,
                height: 200,
                filter: "lanczos3".into(),
            }),
            adjust: crate::pipeline::AdjustSpec {
                brightness: 0.1,
                saturation: -0.2,
                blur: 1.5,
                sharpen: 0.8,
                ..Default::default()
            },
            ..Default::default()
        };

        let performed = actions_for(&pipeline, true, (150, 200));
        let names: Vec<&str> = performed.iter().map(|a| a.action.as_str()).collect();

        assert_eq!(
            names,
            vec![
                "c2pa.opened",
                "c2pa.orientation", // quarter turn + flip
                "c2pa.orientation", // free rotation, a separate resample
                "c2pa.cropped",
                "c2pa.resized",
                "c2pa.adjustedColor",
                "c2pa.enhanced", // sharpen
                "c2pa.filtered", // blur
            ]
        );
        assert!(!is_untouched(&pipeline));
    }

    #[test]
    fn actions_carry_the_specifics_not_just_a_name() {
        // The whole value of the actions assertion is that a reader can see
        // what happened, so a bare action name is not enough.
        let pipeline = Pipeline {
            crop: Some(Crop {
                x: 5,
                y: 6,
                width: 70,
                height: 80,
            }),
            ..Default::default()
        };
        let actions = actions_for(&pipeline, true, (70, 80));
        let crop = actions.iter().find(|a| a.action == "c2pa.cropped").unwrap();

        assert_eq!(
            crop.description.as_deref(),
            Some("cropped to 70x80 at (5, 6)")
        );
        let width = crop
            .parameters
            .iter()
            .find(|(key, _)| key == "com.a10city.width")
            .map(|(_, value)| value.clone());
        assert_eq!(width, Some(Value::Uint(70)));
    }

    #[test]
    fn entity_specific_parameters_use_a_reversed_domain() {
        // Section 6.2.1: anything outside the c2pa namespace has to be
        // namespaced to whoever defined it.
        let pipeline = Pipeline {
            quarter_turns: 2,
            ..Default::default()
        };
        for action in actions_for(&pipeline, true, (10, 10)) {
            for (key, _) in &action.parameters {
                let known = ["ingredients", "digitalSourceType", "description"];
                assert!(
                    known.contains(&key.as_str()) || key.starts_with("com.a10city."),
                    "parameter {key} is neither predefined nor namespaced"
                );
            }
        }
    }

    #[test]
    fn grayscale_alone_still_counts_as_an_edit() {
        let pipeline = Pipeline {
            adjust: crate::pipeline::AdjustSpec {
                grayscale: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!is_untouched(&pipeline));
        assert!(actions_for(&pipeline, true, (10, 10))
            .iter()
            .any(|a| a.action == "c2pa.adjustedColor"));
    }

    #[test]
    fn a_full_turn_is_not_an_edit() {
        let pipeline = Pipeline {
            quarter_turns: 4,
            ..Default::default()
        };
        assert!(is_untouched(&pipeline));
        assert_eq!(actions_for(&pipeline, true, (10, 10)).len(), 1);
    }
}
