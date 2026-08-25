//! The edit pipeline.
//!
//! Edits are described declaratively and always replayed from the pristine
//! decoded source, so dragging the rotation dial after a resize never stacks
//! resampling error - there is exactly one resample between the original
//! pixels and whatever you are looking at.
//!
//! Order of operations:
//!
//! ```text
//!   source > flip > quarter turns > free rotate > crop > resize > adjust
//!                                              \________/
//!                                        "crop space": the frame that
//!                                        crop rectangles are measured in
//! ```
//!
//! Crop deliberately comes *after* rotation. Straightening a photo and then
//! trimming the transparent wedges is the whole point of a free rotation, and
//! it means a crop rectangle is expressed in the coordinates the user is
//! actually looking at rather than some pre-transform frame they cannot see.

use std::borrow::Cow;

use image::{Rgba, RgbaImage};
use serde::Deserialize;

use crate::ops::{self, Adjustments, Resample, WarpQuality};
use crate::Error;

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Crop {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resize {
    pub width: u32,
    pub height: u32,
    #[serde(default = "default_filter")]
    pub filter: String,
}

fn default_filter() -> String {
    "lanczos3".to_string()
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AdjustSpec {
    pub brightness: f32,
    pub contrast: f32,
    pub saturation: f32,
    pub grayscale: bool,
    pub invert: bool,
    pub blur: f32,
    pub sharpen: f32,
}

impl From<AdjustSpec> for Adjustments {
    fn from(s: AdjustSpec) -> Self {
        Adjustments {
            brightness: s.brightness,
            contrast: s.contrast,
            saturation: s.saturation,
            grayscale: s.grayscale,
            invert: s.invert,
            blur: s.blur,
            sharpen: s.sharpen,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Pipeline {
    /// Rectangle in crop space - i.e. after the flips and rotations below.
    pub crop: Option<Crop>,
    pub flip_h: bool,
    pub flip_v: bool,
    /// 90-degree clockwise steps, 0..=3.
    pub quarter_turns: u32,
    /// Free rotation in degrees clockwise, applied after the quarter turns.
    pub angle: f32,
    /// RGBA matte revealed by a free rotation. Defaults to transparent.
    pub background: [u8; 4],
    pub resize: Option<Resize>,
    pub adjust: AdjustSpec,
}

impl Pipeline {
    pub fn parse(json: &str) -> Result<Self, Error> {
        if json.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(json).map_err(|e| Error::BadPipeline(e.to_string()))
    }

    /// Split the requested rotation into lossless quarter turns plus whatever
    /// angle is left over. A dial parked on 90 degrees should transpose the
    /// buffer, not run it through a bicubic resampler and lose sharpness.
    pub(crate) fn split_rotation(&self) -> (u32, f32) {
        let total = self.angle.rem_euclid(360.0);
        let steps = (total / 90.0).round();
        let residual = total - steps * 90.0;
        if residual.abs() < 1e-3 {
            ((self.quarter_turns + steps as u32) % 4, 0.0)
        } else {
            (self.quarter_turns % 4, total)
        }
    }

    /// Size of the frame that crop rectangles are measured against: the source
    /// after flipping and rotating, before any trimming. The UI needs this to
    /// place its selection overlay.
    pub fn crop_space_dims(&self, src_w: u32, src_h: u32) -> (u32, u32) {
        let (mut w, mut h) = (src_w.max(1), src_h.max(1));
        let (quarter_turns, angle) = self.split_rotation();
        if quarter_turns % 2 == 1 {
            std::mem::swap(&mut w, &mut h);
        }
        if angle != 0.0 {
            (w, h) = ops::rotated_extent(w, h, angle);
        }
        (w, h)
    }

    /// Clamp the crop rect to crop space, so a selection left over from a
    /// previous image or a since-changed rotation can never index out of
    /// bounds. Returns `None` when the rect covers everything anyway.
    fn effective_crop(&self, space_w: u32, space_h: u32) -> Option<Crop> {
        let c = self.crop?;
        let x = c.x.min(space_w.saturating_sub(1));
        let y = c.y.min(space_h.saturating_sub(1));
        let width = c.width.min(space_w - x).max(1);
        let height = c.height.min(space_h - y).max(1);
        if x == 0 && y == 0 && width == space_w && height == space_h {
            return None;
        }
        Some(Crop {
            x,
            y,
            width,
            height,
        })
    }

    /// Dimensions the export will have, without touching a single pixel. The
    /// UI calls this on every slider tick to keep the readout live.
    pub fn output_dims(&self, src_w: u32, src_h: u32) -> (u32, u32) {
        let (space_w, space_h) = self.crop_space_dims(src_w, src_h);
        let (w, h) = match self.effective_crop(space_w, space_h) {
            Some(c) => (c.width, c.height),
            None => (space_w, space_h),
        };
        match &self.resize {
            Some(r) => (r.width.max(1), r.height.max(1)),
            None => (w.max(1), h.max(1)),
        }
    }
}

/// The decoded image, plus one cached downscale of it.
///
/// Previewing a 24-megapixel photo means shedding most of those pixels before
/// the warp and the Gaussian ever see them - but redoing that reduction on
/// every frame of a slider drag costs more than everything else combined. So
/// the reduction is cached, and the resolutions it can land on are restricted
/// to successive halvings. Halvings are the highest-quality box reductions
/// available *and* they make the cache key stable: a straighten drag grows the
/// working frame a little on each frame, which would miss a cache keyed on
/// exact dimensions, but stays on the same rung of this ladder.
pub struct SourceCache {
    full: RgbaImage,
    reduced: Option<RgbaImage>,
}

impl SourceCache {
    pub fn new(full: RgbaImage) -> Self {
        Self {
            full,
            reduced: None,
        }
    }

    pub fn dimensions(&self) -> (u32, u32) {
        self.full.dimensions()
    }

    pub fn full(&self) -> &RgbaImage {
        &self.full
    }

    /// The source reduced by `1 / 2^shift`, computed once and reused.
    fn at_shift(&mut self, shift: u32) -> Result<&RgbaImage, Error> {
        if shift == 0 {
            self.reduced = None;
            return Ok(&self.full);
        }

        let width = (self.full.width() >> shift).max(1);
        let height = (self.full.height() >> shift).max(1);

        let stale = match &self.reduced {
            Some(image) => image.dimensions() != (width, height),
            None => true,
        };
        if stale {
            self.reduced = Some(ops::resize(&self.full, width, height, Resample::Box)?);
        }

        Ok(self.reduced.as_ref().expect("just populated"))
    }
}

/// How many halvings the source can take and still have at least as many
/// pixels as the render needs.
fn reduction_shift(needed: f32) -> u32 {
    const MAX_SHIFT: u32 = 6;
    let mut shift = 0;
    while shift < MAX_SHIFT && needed * ((1u32 << (shift + 1)) as f32) <= 1.0 {
        shift += 1;
    }
    shift
}

/// What resolution to render at.
#[derive(Debug, Clone, Copy)]
pub enum Target {
    /// Full output resolution, ready to encode.
    Export,
    /// Fit the composed result inside this box for on-screen display.
    Preview { max_width: u32, max_height: u32 },
}

pub struct Rendered {
    /// Pixels at the rendered resolution.
    pub image: RgbaImage,
    /// Resolution the export would have, which for a preview is larger than
    /// `image`'s own dimensions.
    pub output_width: u32,
    pub output_height: u32,
    /// Frame that crop rectangles are measured against.
    pub crop_space_width: u32,
    pub crop_space_height: u32,
}

/// Run the pipeline over `source`.
pub fn render(
    source: &mut SourceCache,
    pipeline: &Pipeline,
    target: Target,
) -> Result<Rendered, Error> {
    let (src_w, src_h) = source.dimensions();
    if src_w == 0 || src_h == 0 {
        return Err(Error::Geometry("source image is empty".into()));
    }

    let (space_w, space_h) = pipeline.crop_space_dims(src_w, src_h);
    let (output_width, output_height) = pipeline.output_dims(src_w, src_h);
    let (render_w, render_h) = match target {
        Target::Export => (output_width, output_height),
        Target::Preview {
            max_width,
            max_height,
        } => ops::fit_within(
            output_width,
            output_height,
            max_width.max(1),
            max_height.max(1),
        ),
    };
    let warp_quality = match target {
        Target::Export => WarpQuality::Export,
        Target::Preview { .. } => WarpQuality::Preview,
    };

    let region = pipeline.effective_crop(space_w, space_h).unwrap_or(Crop {
        x: 0,
        y: 0,
        width: space_w,
        height: space_h,
    });

    // 1. For previews, shed resolution *before* the affine warp and the
    //    Gaussian - those cost O(pixels), and a 24MP source downsampled to a
    //    900px preview does not need 24MP of warping to look identical.
    //    Exports ask for full resolution, so `reduction_shift` returns 0 and
    //    this borrows the original untouched.
    let needed =
        (render_w as f32 / region.width as f32).max(render_h as f32 / region.height as f32);
    let mut img: Cow<'_, RgbaImage> = Cow::Borrowed(source.at_shift(reduction_shift(needed))?);

    // 2. Lossless orientation, then whatever angle the quarter turns could not
    //    absorb. Each step takes ownership only when it has work to do, so an
    //    untouched pipeline never copies the buffer.
    let (quarter_turns, angle) = pipeline.split_rotation();
    if pipeline.flip_h || pipeline.flip_v || quarter_turns != 0 {
        img = Cow::Owned(ops::orient(
            img.into_owned(),
            pipeline.flip_h,
            pipeline.flip_v,
            quarter_turns,
        ));
    }
    if angle != 0.0 {
        img = Cow::Owned(ops::rotate_free(
            &img,
            angle,
            Rgba(pipeline.background),
            warp_quality,
        )?);
    }

    // 3. Trim. The rect arrives in full-resolution crop space, so it is scaled
    //    by however much resolution step 1 actually shed. Deriving the factor
    //    from the real dimensions rather than the requested ones keeps the
    //    rounding honest.
    if pipeline.effective_crop(space_w, space_h).is_some() {
        let sx = img.width() as f64 / space_w as f64;
        let sy = img.height() as f64 / space_h as f64;

        let x = ((region.x as f64 * sx).round() as u32).min(img.width().saturating_sub(1));
        let y = ((region.y as f64 * sy).round() as u32).min(img.height().saturating_sub(1));
        let w = ((region.width as f64 * sx).round() as u32).clamp(1, img.width() - x);
        let h = ((region.height as f64 * sy).round() as u32).clamp(1, img.height() - y);
        img = Cow::Owned(image::imageops::crop_imm(&*img, x, y, w, h).to_image());
    }

    // 4. Land on the exact requested resolution.
    if img.width() != render_w || img.height() != render_h {
        let filter = pipeline
            .resize
            .as_ref()
            .map(|r| Resample::parse(&r.filter))
            .unwrap_or(Resample::Lanczos3);
        img = Cow::Owned(ops::resize(&img, render_w, render_h, filter)?);
    }

    // 5. Tonal pass, with spatial radii scaled to the render resolution.
    let scale = if output_width == 0 {
        1.0
    } else {
        render_w as f32 / output_width as f32
    };
    let image = ops::adjust(img.into_owned(), &pipeline.adjust.into(), scale);

    Ok(Rendered {
        image,
        output_width,
        output_height,
        crop_space_width: space_w,
        crop_space_height: space_h,
    })
}
