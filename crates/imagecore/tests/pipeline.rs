//! Behavioural tests for the edit pipeline. These run natively (`cargo test`),
//! which keeps them fast and lets CI catch a regression without a browser.

use image::{Rgba, RgbaImage};
use imagecore::codec::{self, EncodeOptions, OutputFormat};
use imagecore::ops::{self, Resample, WarpQuality};
use imagecore::pipeline::{self, Pipeline, SourceCache, Target};

const RED: Rgba<u8> = Rgba([255, 0, 0, 255]);
const BLUE: Rgba<u8> = Rgba([0, 0, 255, 255]);
const CLEAR: Rgba<u8> = Rgba([0, 0, 0, 0]);

/// A 4x2 image: the left half red, the right half blue. Asymmetric on both
/// axes, so every flip and turn is distinguishable.
fn marker() -> RgbaImage {
    let mut img = RgbaImage::from_pixel(4, 2, RED);
    for y in 0..2 {
        for x in 2..4 {
            img.put_pixel(x, y, BLUE);
        }
    }
    // Punch one corner so vertical flips are detectable too.
    img.put_pixel(0, 0, Rgba([0, 255, 0, 255]));
    img
}

fn render(pipeline_json: &str, src: &RgbaImage) -> RgbaImage {
    let p = Pipeline::parse(pipeline_json).expect("pipeline should parse");
    let mut cache = SourceCache::new(src.clone());
    pipeline::render(&mut cache, &p, Target::Export)
        .expect("render should succeed")
        .image
}

#[test]
fn empty_pipeline_is_the_identity() {
    let src = marker();
    let out = render("{}", &src);
    assert_eq!(out.dimensions(), (4, 2));
    assert_eq!(out.as_raw(), src.as_raw());
}

#[test]
fn crop_selects_the_requested_rect() {
    let src = marker();
    let out = render(r#"{"crop":{"x":2,"y":0,"width":2,"height":2}}"#, &src);
    assert_eq!(out.dimensions(), (2, 2));
    assert!(
        out.pixels().all(|p| *p == BLUE),
        "cropped right half is all blue"
    );
}

#[test]
fn crop_is_clamped_to_the_source_instead_of_panicking() {
    let src = marker();
    // A stale selection that runs off both edges.
    let out = render(r#"{"crop":{"x":3,"y":1,"width":9999,"height":9999}}"#, &src);
    assert_eq!(out.dimensions(), (1, 1));
}

#[test]
fn quarter_turns_go_clockwise() {
    let src = marker();
    let out = render(r#"{"quarterTurns":1}"#, &src);
    assert_eq!(out.dimensions(), (2, 4), "a quarter turn swaps the axes");
    // Rotating 4x2 clockwise puts the original top-left corner at the top-right.
    assert_eq!(*out.get_pixel(1, 0), Rgba([0, 255, 0, 255]));
    // The blue right half ends up along the bottom.
    assert_eq!(*out.get_pixel(0, 3), BLUE);
}

#[test]
fn flips_mirror_the_expected_axis() {
    let src = marker();

    let h = render(r#"{"flipH":true}"#, &src);
    assert_eq!(
        *h.get_pixel(0, 0),
        BLUE,
        "horizontal flip brings blue to the left"
    );
    assert_eq!(*h.get_pixel(3, 0), Rgba([0, 255, 0, 255]));

    let v = render(r#"{"flipV":true}"#, &src);
    assert_eq!(
        *v.get_pixel(0, 1),
        Rgba([0, 255, 0, 255]),
        "vertical flip drops the marker"
    );
}

#[test]
fn free_rotation_expands_the_canvas_rather_than_clipping() {
    let src = RgbaImage::from_pixel(100, 100, RED);
    let out =
        ops::rotate_free(&src, 45.0, CLEAR, WarpQuality::Export).expect("rotation should succeed");
    // 100px square turned 45 degrees needs a ~141px canvas to stay whole.
    assert_eq!(out.dimensions(), (142, 142));
    // Corners are outside the rotated square, so they keep the matte colour.
    assert_eq!(*out.get_pixel(0, 0), CLEAR);
    // The centre is still solidly inside the original.
    assert_eq!(out.get_pixel(71, 71).0[0], 255);
}

#[test]
fn free_rotation_turns_clockwise() {
    // A wide bar: after a clockwise quarter-ish turn its mass moves to the
    // vertical axis, and a small clockwise turn lifts the right end upward.
    let mut src = RgbaImage::from_pixel(60, 60, CLEAR);
    for x in 30..60 {
        for y in 28..32 {
            src.put_pixel(x, y, RED);
        }
    }
    let out =
        ops::rotate_free(&src, 30.0, CLEAR, WarpQuality::Export).expect("rotation should succeed");
    let (w, h) = out.dimensions();

    // Centre of mass of the opaque pixels on the right-hand side of the canvas.
    let (mut sum_y, mut count) = (0u64, 0u64);
    for y in 0..h {
        for x in (w * 3 / 4)..w {
            if out.get_pixel(x, y).0[3] > 0 {
                sum_y += y as u64;
                count += 1;
            }
        }
    }
    assert!(count > 0, "the bar should still reach the right edge");
    let mean_y = sum_y as f64 / count as f64;
    assert!(
        mean_y < h as f64 / 2.0,
        "clockwise rotation lifts the right end above centre (mean y = {mean_y}, height = {h})"
    );
}

#[test]
fn rotation_is_a_no_op_at_zero_and_wraps_at_360() {
    let src = marker();
    assert_eq!(render(r#"{"angle":0}"#, &src).as_raw(), src.as_raw());
    assert_eq!(render(r#"{"angle":360}"#, &src).as_raw(), src.as_raw());
}

#[test]
fn resize_hits_the_requested_dimensions_exactly() {
    let src = RgbaImage::from_pixel(640, 480, RED);
    for filter in [
        "nearest",
        "box",
        "bilinear",
        "hamming",
        "catmullrom",
        "mitchell",
        "lanczos3",
    ] {
        let json = format!(r#"{{"resize":{{"width":97,"height":33,"filter":"{filter}"}}}}"#);
        let out = render(&json, &src);
        assert_eq!(
            out.dimensions(),
            (97, 33),
            "filter {filter} should land exactly"
        );
        assert_eq!(
            *out.get_pixel(48, 16),
            RED,
            "filter {filter} should preserve solid colour"
        );
    }
}

#[test]
fn resize_upscales_as_well_as_down() {
    let src = marker();
    let out = render(
        r#"{"resize":{"width":400,"height":200,"filter":"lanczos3"}}"#,
        &src,
    );
    assert_eq!(out.dimensions(), (400, 200));
}

#[test]
fn transparent_edges_do_not_bleed_when_downscaling() {
    // Half opaque red, half fully transparent *green*. Without premultiplied
    // alpha the green would leak into the red edge.
    let mut src = RgbaImage::from_pixel(64, 8, RED);
    for y in 0..8 {
        for x in 32..64 {
            src.put_pixel(x, y, Rgba([0, 255, 0, 0]));
        }
    }
    let out = ops::resize(&src, 8, 2, Resample::Lanczos3).expect("resize should succeed");
    for px in out.pixels() {
        assert!(
            px.0[1] < 40,
            "transparent green must not bleed into the visible edge, got {px:?}"
        );
    }
}

#[test]
fn output_dims_predict_the_render_without_touching_pixels() {
    let cases: &[(&str, (u32, u32))] = &[
        ("{}", (4, 2)),
        (r#"{"crop":{"x":0,"y":0,"width":3,"height":1}}"#, (3, 1)),
        (r#"{"quarterTurns":1}"#, (2, 4)),
        (r#"{"quarterTurns":2}"#, (4, 2)),
        (r#"{"quarterTurns":3}"#, (2, 4)),
        (r#"{"resize":{"width":10,"height":20}}"#, (10, 20)),
        // Crop space for a quarter-turned 4x2 is 2x4, so a 2-wide rect
        // starting at x=1 gets clamped to 1 column.
        (
            r#"{"crop":{"x":1,"y":0,"width":2,"height":2},"quarterTurns":1}"#,
            (1, 2),
        ),
        (r#"{"angle":90}"#, (2, 4)),
    ];

    let src = marker();
    for (json, expected) in cases {
        let p = Pipeline::parse(json).expect("pipeline should parse");
        assert_eq!(p.output_dims(4, 2), *expected, "prediction for {json}");
        let out = render(json, &src);
        assert_eq!(out.dimensions(), *expected, "actual render for {json}");
    }
}

#[test]
fn preview_matches_the_export_geometry_but_not_its_resolution() {
    let src = RgbaImage::from_pixel(2000, 1000, RED);
    let p = Pipeline::parse(r#"{"quarterTurns":1}"#).unwrap();
    let out = pipeline::render(
        &mut SourceCache::new(src.clone()),
        &p,
        Target::Preview {
            max_width: 200,
            max_height: 200,
        },
    )
    .expect("preview should render");

    assert_eq!(
        (out.output_width, out.output_height),
        (1000, 2000),
        "reports export size"
    );
    assert_eq!(
        out.image.dimensions(),
        (100, 200),
        "renders fitted to the box"
    );
}

#[test]
fn preview_never_upscales_past_the_export_resolution() {
    let src = RgbaImage::from_pixel(10, 10, RED);
    let p = Pipeline::parse("{}").unwrap();
    let out = pipeline::render(
        &mut SourceCache::new(src.clone()),
        &p,
        Target::Preview {
            max_width: 900,
            max_height: 900,
        },
    )
    .unwrap();
    assert_eq!(out.image.dimensions(), (10, 10));
}

#[test]
fn adjustments_move_tone_in_the_right_direction() {
    let src = RgbaImage::from_pixel(8, 8, Rgba([100, 100, 100, 255]));

    let brighter = render(r#"{"adjust":{"brightness":0.2}}"#, &src);
    assert!(brighter.get_pixel(0, 0).0[0] > 100);

    let darker = render(r#"{"adjust":{"brightness":-0.2}}"#, &src);
    assert!(darker.get_pixel(0, 0).0[0] < 100);

    // 100 sits below mid-grey, so more contrast pushes it further down.
    let punchy = render(r#"{"adjust":{"contrast":0.5}}"#, &src);
    assert!(punchy.get_pixel(0, 0).0[0] < 100);

    let inverted = render(r#"{"adjust":{"invert":true}}"#, &src);
    assert_eq!(inverted.get_pixel(0, 0).0[0], 155);
}

#[test]
fn desaturating_a_colour_lands_on_its_luma() {
    let src = RgbaImage::from_pixel(4, 4, Rgba([255, 0, 0, 255]));
    let gray = render(r#"{"adjust":{"grayscale":true}}"#, &src);
    let px = gray.get_pixel(0, 0);
    assert_eq!(px.0[0], px.0[1]);
    assert_eq!(px.0[1], px.0[2]);
    // Rec.709 luma of pure red is 0.2126 * 255 ~= 54.
    assert!(
        (px.0[0] as i32 - 54).abs() <= 1,
        "expected ~54, got {}",
        px.0[0]
    );

    // Full desaturation via the slider should agree with the grayscale switch.
    let slid = render(r#"{"adjust":{"saturation":-1}}"#, &src);
    assert!((slid.get_pixel(0, 0).0[0] as i32 - px.0[0] as i32).abs() <= 1);
}

#[test]
fn blur_softens_a_hard_edge() {
    let mut src = RgbaImage::from_pixel(32, 32, RED);
    for y in 0..32 {
        for x in 16..32 {
            src.put_pixel(x, y, BLUE);
        }
    }
    let out = render(r#"{"adjust":{"blur":4}}"#, &src);
    let edge = out.get_pixel(16, 16);
    assert!(
        edge.0[0] > 20 && edge.0[2] > 20,
        "the seam should mix, got {edge:?}"
    );
}

#[test]
fn alpha_survives_the_whole_pipeline() {
    let src = RgbaImage::from_pixel(20, 20, Rgba([10, 200, 30, 128]));
    let out = render(
        r#"{"quarterTurns":1,"resize":{"width":7,"height":7},"adjust":{"brightness":0.1}}"#,
        &src,
    );
    assert_eq!(
        out.get_pixel(3, 3).0[3],
        128,
        "alpha should be carried through"
    );
}

// ---------------------------------------------------------------------------
// Codec round-trips
// ---------------------------------------------------------------------------

fn photo() -> RgbaImage {
    // A gradient, which is far more revealing about codec bugs than flat fill.
    RgbaImage::from_fn(64, 48, |x, y| {
        Rgba([(x * 4) as u8, (y * 5) as u8, ((x + y) * 2) as u8, 255])
    })
}

#[test]
fn every_advertised_output_format_encodes_and_reads_back() {
    let img = photo();
    let opts = EncodeOptions::default();

    for name in [
        "png", "jpeg", "webp", "gif", "tiff", "bmp", "tga", "qoi", "pnm", "farbfeld",
    ] {
        let format = OutputFormat::parse(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let bytes = codec::encode(&img, format, &opts)
            .unwrap_or_else(|e| panic!("encoding {name} failed: {e}"));
        assert!(!bytes.is_empty(), "{name} produced no bytes");

        let decoded = codec::decode(&bytes, Some(name))
            .unwrap_or_else(|e| panic!("re-reading {name} failed: {e}"));
        assert_eq!(
            decoded.image.dimensions(),
            img.dimensions(),
            "{name} changed the dimensions"
        );
    }
}

#[test]
fn ico_encodes_within_its_size_limit_and_refuses_beyond_it() {
    let opts = EncodeOptions::default();
    let small = RgbaImage::from_pixel(64, 64, RED);
    assert!(codec::encode(&small, OutputFormat::Ico, &opts).is_ok());

    let big = RgbaImage::from_pixel(512, 512, RED);
    let err = codec::encode(&big, OutputFormat::Ico, &opts)
        .expect_err("ICO should reject oversized input")
        .to_string();
    assert!(
        err.contains("256"),
        "the error should explain the limit: {err}"
    );
}

#[test]
fn jpeg_quality_actually_changes_the_file_size() {
    let img = photo();
    let low = codec::encode(
        &img,
        OutputFormat::Jpeg,
        &EncodeOptions {
            quality: 20,
            ..Default::default()
        },
    )
    .unwrap();
    let high = codec::encode(
        &img,
        OutputFormat::Jpeg,
        &EncodeOptions {
            quality: 95,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        low.len() < high.len(),
        "q20 {} should beat q95 {}",
        low.len(),
        high.len()
    );
}

#[test]
fn formats_without_alpha_get_flattened_onto_the_matte() {
    // Fully transparent input: JPEG has nowhere to put the alpha, so the matte
    // colour is what must come out.
    let img = RgbaImage::from_pixel(16, 16, Rgba([255, 0, 0, 0]));
    let bytes = codec::encode(
        &img,
        OutputFormat::Jpeg,
        &EncodeOptions {
            background: [0, 0, 255],
            ..Default::default()
        },
    )
    .unwrap();
    let decoded = codec::decode(&bytes, Some("jpeg")).unwrap();
    let px = decoded.image.get_pixel(8, 8);
    assert!(
        px.0[2] > 200 && px.0[0] < 60,
        "expected the blue matte, got {px:?}"
    );
}

#[test]
fn unknown_output_format_is_reported_not_panicked() {
    let err = OutputFormat::parse("jxl")
        .expect_err("jxl is not compiled in")
        .to_string();
    assert!(
        err.contains("jxl"),
        "the error should name the format: {err}"
    );
}

#[test]
fn a_zero_sized_render_is_refused_rather_than_encoded() {
    let empty = RgbaImage::new(0, 0);
    assert!(codec::encode(&empty, OutputFormat::Png, &EncodeOptions::default()).is_err());
}

#[test]
fn malformed_input_produces_a_readable_error() {
    let err = match codec::decode(b"this is definitely not an image", None) {
        Ok(_) => panic!("garbage should not decode"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.to_lowercase().contains("decode"),
        "unhelpful error: {err}"
    );
}

#[test]
fn malformed_pipeline_json_is_reported_not_panicked() {
    assert!(Pipeline::parse("{ not json").is_err());
    // An empty spec is legal and means "no edits".
    assert!(Pipeline::parse("").is_ok());
}

#[test]
fn fit_within_preserves_aspect_and_never_upscales() {
    assert_eq!(ops::fit_within(1000, 500, 100, 100), (100, 50));
    assert_eq!(ops::fit_within(500, 1000, 100, 100), (50, 100));
    assert_eq!(ops::fit_within(40, 20, 100, 100), (40, 20));
    assert_eq!(ops::fit_within(0, 0, 100, 100), (1, 1));
}

#[test]
fn a_large_source_previews_through_the_prescale_path() {
    // Big enough that the pipeline takes its "shed resolution first" branch.
    let src = RgbaImage::from_fn(3000, 2000, |x, y| {
        Rgba([(x % 256) as u8, (y % 256) as u8, 90, 255])
    });
    let p = Pipeline::parse(r#"{"angle":15,"adjust":{"blur":6}}"#).unwrap();
    let out = pipeline::render(
        &mut SourceCache::new(src.clone()),
        &p,
        Target::Preview {
            max_width: 300,
            max_height: 300,
        },
    )
    .expect("preview should render");

    let (ow, oh) = (out.output_width, out.output_height);
    assert!(
        ow > 3000 && oh > 2000,
        "rotation expands the export canvas: {ow}x{oh}"
    );
    assert!(out.image.width() <= 300 && out.image.height() <= 300);
    // Aspect ratio of the preview must track the export.
    let export_aspect = ow as f64 / oh as f64;
    let preview_aspect = out.image.width() as f64 / out.image.height() as f64;
    assert!((export_aspect - preview_aspect).abs() < 0.02);
}

// ---------------------------------------------------------------------------
// Crop space: rectangles are measured after the flips and rotations
// ---------------------------------------------------------------------------

#[test]
fn crop_space_tracks_the_rotation() {
    let p = Pipeline::parse("{}").unwrap();
    assert_eq!(p.crop_space_dims(400, 300), (400, 300));

    let p = Pipeline::parse(r#"{"quarterTurns":1}"#).unwrap();
    assert_eq!(
        p.crop_space_dims(400, 300),
        (300, 400),
        "a quarter turn swaps the frame"
    );

    let p = Pipeline::parse(r#"{"quarterTurns":2}"#).unwrap();
    assert_eq!(p.crop_space_dims(400, 300), (400, 300));

    let p = Pipeline::parse(r#"{"angle":90}"#).unwrap();
    assert_eq!(
        p.crop_space_dims(400, 300),
        (300, 400),
        "90 folds into a quarter turn"
    );

    let p = Pipeline::parse(r#"{"angle":45}"#).unwrap();
    let (w, h) = p.crop_space_dims(100, 100);
    assert_eq!((w, h), (142, 142), "a free angle expands the frame");
}

#[test]
fn cropping_after_a_turn_trims_what_the_user_sees() {
    // 4x2 red/blue marker, turned clockwise into a 2x4 frame. The blue half
    // ends up along the bottom, so the bottom half of crop space is blue.
    let src = marker();
    let out = render(
        r#"{"quarterTurns":1,"crop":{"x":0,"y":2,"width":2,"height":2}}"#,
        &src,
    );
    assert_eq!(out.dimensions(), (2, 2));
    assert!(
        out.pixels().all(|p| *p == BLUE),
        "the bottom of the turned frame is the blue half"
    );
}

#[test]
fn cropping_after_a_free_rotation_can_trim_the_matte_wedges() {
    let src = RgbaImage::from_pixel(100, 100, RED);
    // 100px square at 45 degrees needs a 142px frame; the middle 60px of that
    // frame is entirely inside the rotated square.
    let out = render(
        r#"{"angle":45,"crop":{"x":41,"y":41,"width":60,"height":60}}"#,
        &src,
    );
    assert_eq!(out.dimensions(), (60, 60));
    for px in out.pixels() {
        assert_eq!(px.0[3], 255, "the trimmed centre should have no matte left");
    }
}

#[test]
fn a_crop_covering_everything_is_treated_as_no_crop() {
    let src = marker();
    let out = render(r#"{"crop":{"x":0,"y":0,"width":4,"height":2}}"#, &src);
    assert_eq!(out.as_raw(), src.as_raw());
}

#[test]
fn preview_reports_the_crop_space_the_overlay_needs() {
    let src = RgbaImage::from_pixel(1200, 800, RED);
    let p = Pipeline::parse(r#"{"quarterTurns":1,"crop":{"x":0,"y":0,"width":400,"height":400}}"#)
        .unwrap();
    let out = pipeline::render(
        &mut SourceCache::new(src.clone()),
        &p,
        Target::Preview {
            max_width: 200,
            max_height: 200,
        },
    )
    .unwrap();

    assert_eq!((out.crop_space_width, out.crop_space_height), (800, 1200));
    assert_eq!((out.output_width, out.output_height), (400, 400));
    assert_eq!(out.image.dimensions(), (200, 200));
}

#[test]
fn a_crop_on_a_huge_source_survives_the_prescale_path() {
    // Left half red, right half blue, big enough to trigger the prescale.
    let src = RgbaImage::from_fn(4000, 2000, |x, _| if x < 2000 { RED } else { BLUE });
    let p = Pipeline::parse(r#"{"crop":{"x":2200,"y":200,"width":1600,"height":1600}}"#).unwrap();
    let out = pipeline::render(
        &mut SourceCache::new(src.clone()),
        &p,
        Target::Preview {
            max_width: 120,
            max_height: 120,
        },
    )
    .unwrap();

    assert_eq!((out.output_width, out.output_height), (1600, 1600));
    assert_eq!(out.image.dimensions(), (120, 120));
    // The rect sits entirely in the blue half; if the prescale mis-scaled the
    // rectangle, red would bleed into the left edge of the result.
    for px in out.image.pixels() {
        assert!(
            px.0[2] > 200 && px.0[0] < 60,
            "expected blue throughout, got {px:?}"
        );
    }
}

#[test]
fn gif_quality_trades_encoder_effort_for_speed() {
    // The slider drives NeuQuant's effort dial. Both ends must produce a
    // readable GIF; only the time spent differs.
    let img = photo();
    for quality in [1u8, 50, 100] {
        let bytes = codec::encode(
            &img,
            OutputFormat::Gif,
            &EncodeOptions {
                quality,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("gif at q{quality} failed: {e}"));
        let decoded = codec::decode(&bytes, Some("gif")).unwrap();
        assert_eq!(
            decoded.image.dimensions(),
            img.dimensions(),
            "gif at q{quality}"
        );
    }
}

// ---------------------------------------------------------------------------
// The reduction cache
// ---------------------------------------------------------------------------

#[test]
fn the_reduction_cache_does_not_change_what_gets_rendered() {
    // A cache that is reused across differing pipelines must produce exactly
    // what a cold cache would. Renders a sequence, then replays each step
    // against a fresh cache and compares.
    let src = RgbaImage::from_fn(2400, 1600, |x, y| {
        Rgba([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8, 255])
    });

    let steps = [
        r#"{"angle":3}"#,
        r#"{"angle":7.5}"#,
        r#"{"angle":7.5,"adjust":{"saturation":0.4}}"#,
        r#"{"angle":12,"crop":{"x":100,"y":100,"width":900,"height":700}}"#,
        r#"{"quarterTurns":1}"#,
        r#"{}"#,
    ];

    let mut warm = SourceCache::new(src.clone());
    for json in steps {
        let p = Pipeline::parse(json).unwrap();
        let target = Target::Preview {
            max_width: 400,
            max_height: 400,
        };

        let warm_frame = pipeline::render(&mut warm, &p, target).unwrap();
        let cold_frame = pipeline::render(&mut SourceCache::new(src.clone()), &p, target).unwrap();

        assert_eq!(
            warm_frame.image.dimensions(),
            cold_frame.image.dimensions(),
            "dimensions drifted for {json}"
        );
        assert_eq!(
            warm_frame.image.as_raw(),
            cold_frame.image.as_raw(),
            "a warm cache rendered {json} differently from a cold one"
        );
    }
}

#[test]
fn exports_are_rendered_from_the_full_resolution_source() {
    // Whatever the cache holds from previewing, an export must come from the
    // original pixels - never from a reduction.
    let src = RgbaImage::from_fn(2000, 1200, |x, y| {
        Rgba([(x % 251) as u8, (y % 241) as u8, 40, 255])
    });

    let mut cache = SourceCache::new(src.clone());
    // Warm the cache with a small preview first.
    let p = Pipeline::parse("{}").unwrap();
    pipeline::render(
        &mut cache,
        &p,
        Target::Preview {
            max_width: 200,
            max_height: 200,
        },
    )
    .unwrap();

    let exported = pipeline::render(&mut cache, &p, Target::Export).unwrap();
    assert_eq!(exported.image.dimensions(), (2000, 1200));
    assert_eq!(
        exported.image.as_raw(),
        src.as_raw(),
        "an unedited export must be bit-identical to the source"
    );
}

#[test]
fn a_straighten_drag_keeps_landing_on_the_same_reduction() {
    // The point of a halving ladder: the working frame grows a little on every
    // frame of a drag, and all of them must still reuse one reduction. If the
    // ladder were keyed on exact sizes this would thrash, so assert the render
    // stays fast *and* correct by checking the outputs remain consistent with
    // cold renders.
    let src = RgbaImage::from_fn(1600, 1100, |x, y| {
        Rgba([(x % 256) as u8, (y % 256) as u8, 128, 255])
    });
    let mut cache = SourceCache::new(src.clone());

    for tenth in 0..12 {
        let json = format!(r#"{{"angle":{}}}"#, tenth as f32 * 0.8);
        let p = Pipeline::parse(&json).unwrap();
        let target = Target::Preview {
            max_width: 300,
            max_height: 300,
        };

        let warm = pipeline::render(&mut cache, &p, target).unwrap();
        let cold = pipeline::render(&mut SourceCache::new(src.clone()), &p, target).unwrap();
        assert_eq!(warm.image.as_raw(), cold.image.as_raw(), "drift at {json}");
    }
}
