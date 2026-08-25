//! Decoding and encoding across the popular raster formats.
//!
//! Everything funnels through `image`, which gives us a single dependency for
//! PNG / JPEG / WebP / GIF / TIFF / BMP / ICO / TGA / QOI / PNM / HDR / EXR /
//! DDS instead of a pile of per-format C libraries that would not cross-compile
//! to `wasm32-unknown-unknown`.

use std::io::Cursor;

use image::codecs::gif::GifEncoder;
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::{CompressionType, FilterType as PngFilter, PngEncoder};
use image::codecs::webp::WebPEncoder;
use image::{
    DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, ImageReader, Rgb, RgbImage, RgbaImage,
};

use crate::Error;

/// Formats we accept as input. Anything the browser can decode but `image`
/// cannot (AVIF, HEIC, SVG) reaches us as raw RGBA through `Editor::open_raw`.
pub const INPUT_FORMATS: &[&str] = &[
    "png", "jpeg", "webp", "gif", "bmp", "tiff", "ico", "tga", "qoi", "pnm", "hdr", "farbfeld",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Png,
    Jpeg,
    WebP,
    Gif,
    Bmp,
    Tiff,
    Ico,
    Tga,
    Qoi,
    Pnm,
    Farbfeld,
}

impl OutputFormat {
    pub fn parse(name: &str) -> Result<Self, Error> {
        Ok(match name.trim().to_ascii_lowercase().as_str() {
            "png" => Self::Png,
            "jpeg" | "jpg" => Self::Jpeg,
            "webp" => Self::WebP,
            "gif" => Self::Gif,
            "bmp" => Self::Bmp,
            "tiff" | "tif" => Self::Tiff,
            "ico" => Self::Ico,
            "tga" => Self::Tga,
            "qoi" => Self::Qoi,
            "pnm" | "ppm" => Self::Pnm,
            "farbfeld" | "ff" => Self::Farbfeld,
            other => return Err(Error::UnsupportedOutput(other.to_string())),
        })
    }

    pub fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::WebP => "image/webp",
            Self::Gif => "image/gif",
            Self::Bmp => "image/bmp",
            Self::Tiff => "image/tiff",
            Self::Ico => "image/x-icon",
            Self::Tga => "image/x-tga",
            Self::Qoi => "image/qoi",
            Self::Pnm => "image/x-portable-anymap",
            Self::Farbfeld => "image/farbfeld",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::WebP => "webp",
            Self::Gif => "gif",
            Self::Bmp => "bmp",
            Self::Tiff => "tiff",
            Self::Ico => "ico",
            Self::Tga => "tga",
            Self::Qoi => "qoi",
            Self::Pnm => "ppm",
            Self::Farbfeld => "ff",
        }
    }

    /// Whether the encoder honours the quality slider. GIF counts: its palette
    /// is built by quantisation, and how hard the quantiser works is exactly
    /// the quality/speed trade the slider expresses.
    pub fn is_lossy(self) -> bool {
        matches!(self, Self::Jpeg | Self::Gif)
    }

    /// Whether the encoder can carry an alpha channel. Formats that cannot get
    /// flattened onto the caller's chosen matte colour first.
    pub fn supports_alpha(self) -> bool {
        !matches!(self, Self::Jpeg | Self::Pnm)
    }
}

/// Options that steer the encoders.
#[derive(Debug, Clone)]
pub struct EncodeOptions {
    /// 1-100, used by JPEG.
    pub quality: u8,
    /// `fast` | `default` | `best`, used by PNG.
    pub png_compression: String,
    /// Matte colour used when flattening alpha for formats without it.
    pub background: [u8; 3],
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self {
            quality: 85,
            png_compression: "default".to_string(),
            background: [255, 255, 255],
        }
    }
}

/// Decoded image plus the format label we detected.
pub struct Decoded {
    pub image: RgbaImage,
    pub format: String,
    pub had_alpha: bool,
}

/// Decode an encoded byte stream, honouring the EXIF orientation tag so that
/// phone photos are not silently sideways.
///
/// `hint` is a filename, extension or MIME type. Content sniffing handles most
/// formats, but TGA and a few others carry no leading magic number, so the
/// hint is what lets `holiday.tga` open at all.
pub fn decode(bytes: &[u8], hint: Option<&str>) -> Result<Decoded, Error> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| Error::Decode(e.to_string()))?;

    if reader.format().is_none() {
        match hint.and_then(format_from_hint) {
            Some(format) => reader.set_format(format),
            None => {
                return Err(Error::Decode(
                    "the format could not be identified from the file contents or its name".into(),
                ))
            }
        }
    }

    let format = reader
        .format()
        .map(format_label)
        .unwrap_or("unknown")
        .to_string();

    let mut decoder = reader
        .into_decoder()
        .map_err(|e| Error::Decode(e.to_string()))?;

    // `orientation()` reads the EXIF tag where the codec exposes one and
    // returns `NoTransforms` otherwise, so this is safe for every format.
    let orientation = decoder
        .orientation()
        .unwrap_or(image::metadata::Orientation::NoTransforms);

    let mut image =
        DynamicImage::from_decoder(decoder).map_err(|e| Error::Decode(e.to_string()))?;
    image.apply_orientation(orientation);

    let had_alpha = image.color().has_alpha();

    Ok(Decoded {
        image: image.into_rgba8(),
        format,
        had_alpha,
    })
}

/// Pull a format out of a filename, bare extension or MIME type.
fn format_from_hint(hint: &str) -> Option<ImageFormat> {
    let hint = hint.trim().to_ascii_lowercase();
    if hint.is_empty() {
        return None;
    }
    // "photo.tga" -> "tga", "image/x-tga" -> "x-tga", ".tga" -> "tga"
    let tail = hint
        .rsplit(['.', '/'])
        .next()
        .unwrap_or(&hint)
        .trim_start_matches("x-");
    ImageFormat::from_extension(tail).or_else(|| ImageFormat::from_mime_type(&hint))
}

fn format_label(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Png => "png",
        ImageFormat::Jpeg => "jpeg",
        ImageFormat::Gif => "gif",
        ImageFormat::WebP => "webp",
        ImageFormat::Pnm => "pnm",
        ImageFormat::Tiff => "tiff",
        ImageFormat::Tga => "tga",
        ImageFormat::Bmp => "bmp",
        ImageFormat::Ico => "ico",
        ImageFormat::Hdr => "hdr",
        ImageFormat::Farbfeld => "farbfeld",
        ImageFormat::Avif => "avif",
        ImageFormat::Qoi => "qoi",
        _ => "unknown",
    }
}

/// Composite RGBA over an opaque matte colour.
fn flatten(rgba: &RgbaImage, background: [u8; 3]) -> RgbImage {
    let mut out = RgbImage::new(rgba.width(), rgba.height());
    for (dst, src) in out.pixels_mut().zip(rgba.pixels()) {
        let a = src.0[3] as u32;
        if a == 255 {
            *dst = Rgb([src.0[0], src.0[1], src.0[2]]);
            continue;
        }
        let inv = 255 - a;
        let mix = |c: u8, b: u8| (((c as u32 * a) + (b as u32 * inv) + 127) / 255) as u8;
        *dst = Rgb([
            mix(src.0[0], background[0]),
            mix(src.0[1], background[1]),
            mix(src.0[2], background[2]),
        ]);
    }
    out
}

/// Encode to the requested container. Returns the byte stream ready to be
/// handed to a `Blob` on the JS side.
pub fn encode(
    rgba: &RgbaImage,
    format: OutputFormat,
    opts: &EncodeOptions,
) -> Result<Vec<u8>, Error> {
    if format == OutputFormat::Ico && (rgba.width() > 256 || rgba.height() > 256) {
        return Err(Error::Encode(format!(
            "ICO tops out at 256x256; this image is {}x{}. Resize before exporting.",
            rgba.width(),
            rgba.height()
        )));
    }
    if rgba.width() == 0 || rgba.height() == 0 {
        return Err(Error::Encode(
            "refusing to encode a zero-sized image".into(),
        ));
    }

    let mut out = Cursor::new(Vec::<u8>::new());

    match format {
        OutputFormat::Jpeg => {
            let rgb = flatten(rgba, opts.background);
            let quality = opts.quality.clamp(1, 100);
            let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
            encoder
                .encode(
                    rgb.as_raw(),
                    rgb.width(),
                    rgb.height(),
                    image::ExtendedColorType::Rgb8,
                )
                .map_err(|e| Error::Encode(e.to_string()))?;
        }
        OutputFormat::Png => {
            let compression = match opts.png_compression.as_str() {
                "fast" => CompressionType::Fast,
                "best" => CompressionType::Best,
                _ => CompressionType::Default,
            };
            // Adaptive prediction usually beats a fixed filter on photographic
            // content and costs almost nothing to try.
            PngEncoder::new_with_quality(&mut out, compression, PngFilter::Adaptive)
                .write_image(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    image::ExtendedColorType::Rgba8,
                )
                .map_err(|e| Error::Encode(e.to_string()))?;
        }
        OutputFormat::WebP => {
            // image-webp writes lossless VP8L. Lossy WebP would mean linking
            // libwebp through C, which does not cross-compile here.
            WebPEncoder::new_lossless(&mut out)
                .encode(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    image::ExtendedColorType::Rgba8,
                )
                .map_err(|e| Error::Encode(e.to_string()))?;
        }
        OutputFormat::Pnm => {
            let rgb = flatten(rgba, opts.background);
            DynamicImage::ImageRgb8(rgb)
                .write_to(&mut out, ImageFormat::Pnm)
                .map_err(|e| Error::Encode(e.to_string()))?;
        }
        OutputFormat::Gif => {
            // NeuQuant's effort dial runs 1 (best, and very slow on a large
            // frame) to 30 (fastest). Map the quality slider onto it so a GIF
            // export is not a multi-second stall by default.
            let quality = opts.quality.clamp(1, 100) as u32;
            let speed = (30 - (quality - 1) * 29 / 99).clamp(1, 30) as i32;
            let mut encoder = GifEncoder::new_with_speed(&mut out, speed);
            encoder
                .encode(
                    rgba.as_raw(),
                    rgba.width(),
                    rgba.height(),
                    image::ExtendedColorType::Rgba8,
                )
                .map_err(|e| Error::Encode(e.to_string()))?;
        }
        OutputFormat::Farbfeld => {
            // Farbfeld is 16-bit RGBA only; anything else is rejected outright.
            DynamicImage::ImageRgba8(rgba.clone())
                .into_rgba16()
                .write_to(&mut out, ImageFormat::Farbfeld)
                .map_err(|e| Error::Encode(e.to_string()))?;
        }
        other => {
            let target = match other {
                OutputFormat::Bmp => ImageFormat::Bmp,
                OutputFormat::Tiff => ImageFormat::Tiff,
                OutputFormat::Ico => ImageFormat::Ico,
                OutputFormat::Tga => ImageFormat::Tga,
                OutputFormat::Qoi => ImageFormat::Qoi,
                _ => unreachable!("handled above"),
            };
            DynamicImage::ImageRgba8(rgba.clone())
                .write_to(&mut out, target)
                .map_err(|e| Error::Encode(e.to_string()))?;
        }
    }

    Ok(out.into_inner())
}
