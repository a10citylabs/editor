//! The pixel operators: resampling, affine geometry and tonal adjustments.
//!
//! Resampling goes through `fast_image_resize` because its convolution kernels
//! are vectorised for wasm `simd128`; the affine warp and the separable
//! Gaussian come from `imageproc`, which is the pure-Rust stand-in for the
//! OpenCV routines that cannot be built for this target.

use fast_image_resize::images::{Image as FirImage, ImageRef};
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer};
use image::{Rgba, RgbaImage};
use imageproc::geometric_transformations::{warp_into, Border, Interpolation, Projection};

use crate::Error;

/// Resampling kernels exposed to the UI, ordered cheap -> expensive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resample {
    Nearest,
    Box,
    Bilinear,
    Hamming,
    CatmullRom,
    Mitchell,
    Lanczos3,
}

impl Resample {
    pub fn parse(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "nearest" => Self::Nearest,
            "box" | "area" => Self::Box,
            "bilinear" | "triangle" => Self::Bilinear,
            "hamming" => Self::Hamming,
            "catmullrom" | "catrom" => Self::CatmullRom,
            "mitchell" => Self::Mitchell,
            _ => Self::Lanczos3,
        }
    }

    fn alg(self) -> ResizeAlg {
        match self {
            Self::Nearest => ResizeAlg::Nearest,
            Self::Box => ResizeAlg::Convolution(FilterType::Box),
            Self::Bilinear => ResizeAlg::Convolution(FilterType::Bilinear),
            Self::Hamming => ResizeAlg::Convolution(FilterType::Hamming),
            Self::CatmullRom => ResizeAlg::Convolution(FilterType::CatmullRom),
            Self::Mitchell => ResizeAlg::Convolution(FilterType::Mitchell),
            Self::Lanczos3 => ResizeAlg::Convolution(FilterType::Lanczos3),
        }
    }
}

/// SIMD-accelerated resize. Alpha is premultiplied around the convolution so
/// that transparent edges do not bleed the colour of fully-transparent pixels.
pub fn resize(
    src: &RgbaImage,
    width: u32,
    height: u32,
    filter: Resample,
) -> Result<RgbaImage, Error> {
    let (width, height) = (width.max(1), height.max(1));
    if src.width() == width && src.height() == height {
        return Ok(src.clone());
    }

    let src_view = ImageRef::new(src.width(), src.height(), src.as_raw(), PixelType::U8x4)
        .map_err(|e| Error::Resize(e.to_string()))?;
    let mut dst = FirImage::new(width, height, PixelType::U8x4);

    let options = ResizeOptions::new()
        .resize_alg(filter.alg())
        // Nearest must not premultiply: it copies pixels verbatim and the
        // round-trip through premultiplied space would only lose precision.
        .use_alpha(filter != Resample::Nearest);

    Resizer::new()
        .resize(&src_view, &mut dst, &options)
        .map_err(|e| Error::Resize(e.to_string()))?;

    RgbaImage::from_raw(width, height, dst.into_vec())
        .ok_or_else(|| Error::Resize("resampled buffer had the wrong length".into()))
}

/// Fit `(w, h)` inside `(max_w, max_h)` without distorting it or scaling up.
pub fn fit_within(w: u32, h: u32, max_w: u32, max_h: u32) -> (u32, u32) {
    if w == 0 || h == 0 {
        return (1, 1);
    }
    let scale = (max_w as f64 / w as f64).min(max_h as f64 / h as f64);
    if scale >= 1.0 {
        return (w, h);
    }
    (
        ((w as f64 * scale).round() as u32).max(1),
        ((h as f64 * scale).round() as u32).max(1),
    )
}

/// Quarter turns clockwise, plus the two mirror flips. These are pure memory
/// moves - no resampling, so they are always lossless.
pub fn orient(mut img: RgbaImage, flip_h: bool, flip_v: bool, quarter_turns: u32) -> RgbaImage {
    if flip_h {
        image::imageops::flip_horizontal_in_place(&mut img);
    }
    if flip_v {
        image::imageops::flip_vertical_in_place(&mut img);
    }
    match quarter_turns % 4 {
        1 => image::imageops::rotate90(&img),
        2 => image::imageops::rotate180(&img),
        3 => image::imageops::rotate270(&img),
        _ => img,
    }
}

/// Bounding box of `w x h` turned by `degrees`, as an integer pixel size.
///
/// `output_dims` predicts with this and `rotate_free` allocates with it, so a
/// prediction can never disagree with what actually gets rendered. The nudge
/// to 4 decimal places matters: `cos(90deg)` in f32 is -4.4e-8 rather than 0,
/// and a naive `ceil` would turn a clean 2px into 3px.
pub fn rotated_extent(w: u32, h: u32, degrees: f32) -> (u32, u32) {
    let theta = degrees.rem_euclid(360.0).to_radians();
    let (sin, cos) = (theta.sin().abs(), theta.cos().abs());
    let (w, h) = (w as f32, h as f32);
    (ceil_dim(w * cos + h * sin), ceil_dim(w * sin + h * cos))
}

fn ceil_dim(v: f32) -> u32 {
    (((v * 10_000.0).round() / 10_000.0).ceil()).max(1.0) as u32
}

/// How much the warp should spend per output pixel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarpQuality {
    /// Bilinear: 4 taps. On an image already reduced for the screen the
    /// difference from bicubic is invisible, and it is roughly three times
    /// faster - which is what keeps a straighten drag responsive.
    Preview,
    /// Bicubic: 16 taps. What the file people download is worth.
    Export,
}

impl WarpQuality {
    fn interpolation(self) -> Interpolation {
        match self {
            Self::Preview => Interpolation::Bilinear,
            Self::Export => Interpolation::Bicubic,
        }
    }
}

/// Free rotation by an arbitrary angle, expanding the canvas so no corner is
/// clipped. `degrees` is clockwise, matching how the UI dial reads.
pub fn rotate_free(
    src: &RgbaImage,
    degrees: f32,
    fill: Rgba<u8>,
    quality: WarpQuality,
) -> Result<RgbaImage, Error> {
    let normalised = degrees.rem_euclid(360.0);
    if normalised.abs() < f32::EPSILON {
        return Ok(src.clone());
    }

    let (out_w, out_h) = rotated_extent(src.width(), src.height(), normalised);
    if out_w > u16::MAX as u32 || out_h > u16::MAX as u32 {
        return Err(Error::Geometry(
            "rotated canvas would exceed 65535px on a side".into(),
        ));
    }
    let (out_wf, out_hf) = (out_w as f32, out_h as f32);
    let (w, h) = (src.width() as f32, src.height() as f32);

    // Compose source-centre -> origin -> rotate -> destination-centre.
    // `Projection::rotate` is counter-clockwise, so the angle is negated to
    // make a positive dial reading turn the picture clockwise.
    let projection = Projection::translate(out_wf / 2.0, out_hf / 2.0)
        * Projection::rotate(-normalised.to_radians())
        * Projection::translate(-w / 2.0, -h / 2.0);

    let mut out = RgbaImage::from_pixel(out_w, out_h, fill);
    warp_into(
        src,
        projection,
        quality.interpolation(),
        Border::Constant(fill),
        &mut out,
    );
    Ok(out)
}

/// Tonal controls. Every slider is normalised to -1.0 ..= 1.0 with 0.0 as the
/// identity so the UI can treat them uniformly.
#[derive(Debug, Clone, Copy, Default)]
pub struct Adjustments {
    pub brightness: f32,
    pub contrast: f32,
    pub saturation: f32,
    pub grayscale: bool,
    pub invert: bool,
    /// Gaussian sigma in output pixels; 0 disables.
    pub blur: f32,
    /// Unsharp-mask amount; 0 disables.
    pub sharpen: f32,
}

impl Adjustments {
    pub fn is_identity(&self) -> bool {
        self.brightness == 0.0
            && self.contrast == 0.0
            && self.saturation == 0.0
            && !self.grayscale
            && !self.invert
            && self.blur <= 0.0
            && self.sharpen <= 0.0
    }
}

/// Apply the tonal stack. `scale` shrinks the spatial radii so a preview
/// rendered at 1/4 size still looks like the full-resolution export.
pub fn adjust(mut img: RgbaImage, a: &Adjustments, scale: f32) -> RgbaImage {
    if a.is_identity() {
        return img;
    }

    if a.brightness != 0.0 || a.contrast != 0.0 {
        let lut = tone_lut(a.brightness, a.contrast);
        for px in img.pixels_mut() {
            px.0[0] = lut[px.0[0] as usize];
            px.0[1] = lut[px.0[1] as usize];
            px.0[2] = lut[px.0[2] as usize];
        }
    }

    if a.saturation != 0.0 {
        let factor = 1.0 + a.saturation.clamp(-1.0, 1.0);
        for px in img.pixels_mut() {
            let (r, g, b) = (px.0[0] as f32, px.0[1] as f32, px.0[2] as f32);
            let luma = 0.2126 * r + 0.7152 * g + 0.0722 * b;
            px.0[0] = clamp_u8(luma + (r - luma) * factor);
            px.0[1] = clamp_u8(luma + (g - luma) * factor);
            px.0[2] = clamp_u8(luma + (b - luma) * factor);
        }
    }

    if a.grayscale {
        for px in img.pixels_mut() {
            let luma = 0.2126 * px.0[0] as f32 + 0.7152 * px.0[1] as f32 + 0.0722 * px.0[2] as f32;
            let v = clamp_u8(luma);
            px.0[0] = v;
            px.0[1] = v;
            px.0[2] = v;
        }
    }

    if a.invert {
        for px in img.pixels_mut() {
            px.0[0] = 255 - px.0[0];
            px.0[1] = 255 - px.0[1];
            px.0[2] = 255 - px.0[2];
        }
    }

    let scale = scale.clamp(0.01, 1.0);
    if a.blur > 0.0 {
        let sigma = (a.blur * scale).max(0.1);
        img = imageproc::filter::gaussian_blur_f32(&img, sigma);
    }
    if a.sharpen > 0.0 {
        // A 1.4px radius is the classic unsharp default; scaling it keeps the
        // preview honest about how much crunch the export will have.
        let sigma = (1.4 * scale).max(0.3);
        img = unsharp_mask(&img, sigma, a.sharpen);
    }

    img
}

/// Unsharp masking over colour. imageproc only ships a grayscale variant, and
/// running it per channel via `Luma` round-trips would cost three extra
/// allocations, so the blur is shared and the add-back is done inline.
/// Alpha is deliberately left untouched - sharpening a matte carves halos into
/// the edges of a cut-out.
fn unsharp_mask(img: &RgbaImage, sigma: f32, amount: f32) -> RgbaImage {
    let blurred = imageproc::filter::gaussian_blur_f32(img, sigma);
    let mut out = img.clone();
    for (dst, blur) in out.pixels_mut().zip(blurred.pixels()) {
        for c in 0..3 {
            let sharp = dst.0[c] as f32;
            let soft = blur.0[c] as f32;
            dst.0[c] = clamp_u8(sharp + (sharp - soft) * amount);
        }
    }
    out
}

/// Brightness offset then a contrast slope pivoted on mid-grey, baked into a
/// 256-entry table so the per-pixel loop stays branch-free.
fn tone_lut(brightness: f32, contrast: f32) -> [u8; 256] {
    let offset = brightness.clamp(-1.0, 1.0) * 255.0;
    let c = contrast.clamp(-0.99, 0.99);
    let slope = (1.0 + c) / (1.0 - c);

    let mut lut = [0u8; 256];
    for (i, slot) in lut.iter_mut().enumerate() {
        let v = i as f32 + offset;
        *slot = clamp_u8((v - 128.0) * slope + 128.0);
    }
    lut
}

#[inline]
fn clamp_u8(v: f32) -> u8 {
    v.clamp(0.0, 255.0).round() as u8
}
