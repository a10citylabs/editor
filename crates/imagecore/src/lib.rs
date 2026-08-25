//! # imagecore
//!
//! The WebAssembly engine behind the A10city Image Editor.
//!
//! Everything runs in the browser: bytes go in, edited bytes come out, and no
//! pixel ever leaves the tab. The public surface is deliberately small - open
//! an image once, then describe the edit you want as a JSON pipeline and ask
//! for either a screen-sized preview or a full-resolution export.
//!
//! ```text
//!   bytes ──▶ Editor::open ──▶ [ crop ▸ flip ▸ rotate ▸ resize ▸ adjust ] ──▶ encode
//!                                  ▲
//!                        replayed from the pristine source every time
//! ```

use image::RgbaImage;
use wasm_bindgen::prelude::*;

pub mod codec;
pub mod ops;
pub mod pipeline;

use codec::{EncodeOptions, OutputFormat};
use pipeline::{Pipeline, SourceCache, Target};

/// Everything that can go wrong, with a message meant to be read by a person.
#[derive(Debug)]
pub enum Error {
    Decode(String),
    Encode(String),
    Resize(String),
    Geometry(String),
    BadPipeline(String),
    UnsupportedOutput(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(m) => write!(f, "Could not decode this image: {m}"),
            Self::Encode(m) => write!(f, "Could not encode the result: {m}"),
            Self::Resize(m) => write!(f, "Resampling failed: {m}"),
            Self::Geometry(m) => write!(f, "Invalid geometry: {m}"),
            Self::BadPipeline(m) => write!(f, "Malformed edit pipeline: {m}"),
            Self::UnsupportedOutput(m) => write!(f, "'{m}' is not a supported output format"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "panic-hook")]
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// A decoded image plus the operations to replay over it.
#[wasm_bindgen]
pub struct Editor {
    source: SourceCache,
    source_format: String,
    had_alpha: bool,
}

#[wasm_bindgen]
impl Editor {
    /// Decode an encoded file. Handles PNG, JPEG, WebP, GIF, TIFF, BMP, ICO,
    /// TGA, QOI, PNM, HDR, OpenEXR and DDS, and applies the EXIF orientation
    /// tag so camera rolls come in upright.
    ///
    /// `hint` should be the original filename or MIME type. Content sniffing
    /// covers most formats; TGA has no leading magic number, so without the
    /// hint it cannot be identified at all.
    #[wasm_bindgen(js_name = open)]
    pub fn open(bytes: &[u8], hint: Option<String>) -> Result<Editor, JsError> {
        let decoded = codec::decode(bytes, hint.as_deref())?;
        Ok(Editor {
            source: SourceCache::new(decoded.image),
            source_format: decoded.format,
            had_alpha: decoded.had_alpha,
        })
    }

    /// Adopt raw RGBA that the host already decoded. This is the escape hatch
    /// for AVIF, HEIC and SVG: the browser has decoders for those built in, so
    /// we let it hand us pixels rather than shipping another megabyte of wasm.
    #[wasm_bindgen(js_name = openRaw)]
    pub fn open_raw(
        pixels: Vec<u8>,
        width: u32,
        height: u32,
        label: String,
    ) -> Result<Editor, JsError> {
        let expected = width as usize * height as usize * 4;
        if pixels.len() != expected {
            return Err(Error::Decode(format!(
                "expected {expected} bytes of RGBA for {width}x{height}, got {}",
                pixels.len()
            ))
            .into());
        }
        let source = RgbaImage::from_raw(width, height, pixels)
            .ok_or_else(|| Error::Decode("could not adopt the RGBA buffer".into()))?;
        Ok(Editor {
            source: SourceCache::new(source),
            source_format: label,
            had_alpha: true,
        })
    }

    #[wasm_bindgen(getter, js_name = sourceWidth)]
    pub fn source_width(&self) -> u32 {
        self.source.dimensions().0
    }

    #[wasm_bindgen(getter, js_name = sourceHeight)]
    pub fn source_height(&self) -> u32 {
        self.source.dimensions().1
    }

    #[wasm_bindgen(getter, js_name = sourceFormat)]
    pub fn source_format(&self) -> String {
        self.source_format.clone()
    }

    #[wasm_bindgen(getter, js_name = hasAlpha)]
    pub fn has_alpha(&self) -> bool {
        self.had_alpha
    }

    /// Geometry the UI needs to draw itself, computed without touching a
    /// single pixel: the export resolution, and the frame that crop rectangles
    /// are measured against. Returns
    /// `{"width":…,"height":…,"cropSpaceWidth":…,"cropSpaceHeight":…}`.
    #[wasm_bindgen(js_name = outputDims)]
    pub fn output_dims(&self, pipeline_json: &str) -> Result<String, JsError> {
        let pipeline = Pipeline::parse(pipeline_json)?;
        let (src_w, src_h) = self.source.dimensions();
        let (w, h) = pipeline.output_dims(src_w, src_h);
        let (cw, ch) = pipeline.crop_space_dims(src_w, src_h);
        Ok(format!(
            "{{\"width\":{w},\"height\":{h},\"cropSpaceWidth\":{cw},\"cropSpaceHeight\":{ch}}}"
        ))
    }

    /// Compose the edit at screen resolution. Cheap enough to call on every
    /// slider drag: a 6000x4000 source previews in a few milliseconds because
    /// the resolution is shed before the expensive operators run.
    #[wasm_bindgen(js_name = renderPreview)]
    pub fn render_preview(
        &mut self,
        pipeline_json: &str,
        max_width: u32,
        max_height: u32,
    ) -> Result<PreviewFrame, JsError> {
        let pipeline = Pipeline::parse(pipeline_json)?;
        let rendered = pipeline::render(
            &mut self.source,
            &pipeline,
            Target::Preview {
                max_width,
                max_height,
            },
        )?;
        Ok(PreviewFrame {
            width: rendered.image.width(),
            height: rendered.image.height(),
            output_width: rendered.output_width,
            output_height: rendered.output_height,
            crop_space_width: rendered.crop_space_width,
            crop_space_height: rendered.crop_space_height,
            pixels: rendered.image.into_raw(),
        })
    }

    /// Compose at full resolution and encode. `encode_json` accepts
    /// `{"format":"jpeg","quality":85,"pngCompression":"default","background":[255,255,255]}`.
    #[wasm_bindgen(js_name = renderExport)]
    pub fn render_export(
        &mut self,
        pipeline_json: &str,
        encode_json: &str,
    ) -> Result<ExportResult, JsError> {
        let pipeline = Pipeline::parse(pipeline_json)?;
        let request: EncodeRequest = if encode_json.trim().is_empty() {
            EncodeRequest::default()
        } else {
            serde_json::from_str(encode_json).map_err(|e| Error::BadPipeline(e.to_string()))?
        };

        let format = OutputFormat::parse(&request.format)?;
        let rendered = pipeline::render(&mut self.source, &pipeline, Target::Export)?;
        let (width, height) = (rendered.image.width(), rendered.image.height());

        let opts = EncodeOptions {
            quality: request.quality,
            png_compression: request.png_compression,
            background: request.background,
        };
        let bytes = codec::encode(&rendered.image, format, &opts)?;

        Ok(ExportResult {
            width,
            height,
            mime: format.mime().to_string(),
            extension: format.extension().to_string(),
            bytes,
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncodeRequest {
    #[serde(default = "default_format")]
    format: String,
    #[serde(default = "default_quality")]
    quality: u8,
    #[serde(default = "default_png_compression")]
    png_compression: String,
    #[serde(default = "default_background")]
    background: [u8; 3],
}

impl Default for EncodeRequest {
    fn default() -> Self {
        Self {
            format: default_format(),
            quality: default_quality(),
            png_compression: default_png_compression(),
            background: default_background(),
        }
    }
}

fn default_format() -> String {
    "png".into()
}
fn default_quality() -> u8 {
    85
}
fn default_png_compression() -> String {
    "default".into()
}
fn default_background() -> [u8; 3] {
    [255, 255, 255]
}

/// A composed frame at display resolution, ready for `putImageData`.
#[wasm_bindgen]
pub struct PreviewFrame {
    width: u32,
    height: u32,
    output_width: u32,
    output_height: u32,
    crop_space_width: u32,
    crop_space_height: u32,
    pixels: Vec<u8>,
}

#[wasm_bindgen]
impl PreviewFrame {
    #[wasm_bindgen(getter)]
    pub fn width(&self) -> u32 {
        self.width
    }
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> u32 {
        self.height
    }
    /// Full-resolution width the export would have.
    #[wasm_bindgen(getter, js_name = outputWidth)]
    pub fn output_width(&self) -> u32 {
        self.output_width
    }
    #[wasm_bindgen(getter, js_name = outputHeight)]
    pub fn output_height(&self) -> u32 {
        self.output_height
    }
    /// Width of the frame crop rectangles are measured against.
    #[wasm_bindgen(getter, js_name = cropSpaceWidth)]
    pub fn crop_space_width(&self) -> u32 {
        self.crop_space_width
    }
    #[wasm_bindgen(getter, js_name = cropSpaceHeight)]
    pub fn crop_space_height(&self) -> u32 {
        self.crop_space_height
    }
    /// Moves the RGBA buffer out to JS, leaving this frame empty.
    #[wasm_bindgen(js_name = takePixels)]
    pub fn take_pixels(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pixels)
    }
}

/// An encoded file, ready to become a `Blob`.
#[wasm_bindgen]
pub struct ExportResult {
    width: u32,
    height: u32,
    mime: String,
    extension: String,
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl ExportResult {
    #[wasm_bindgen(getter)]
    pub fn width(&self) -> u32 {
        self.width
    }
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> u32 {
        self.height
    }
    #[wasm_bindgen(getter)]
    pub fn mime(&self) -> String {
        self.mime.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn extension(&self) -> String {
        self.extension.clone()
    }
    #[wasm_bindgen(getter, js_name = byteLength)]
    pub fn byte_length(&self) -> u32 {
        self.bytes.len() as u32
    }
    /// Moves the encoded bytes out to JS, leaving this result empty.
    #[wasm_bindgen(js_name = takeBytes)]
    pub fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

/// What this build can read and write, so the UI never offers a format the
/// engine was not compiled with. Returns JSON.
#[wasm_bindgen]
pub fn capabilities() -> String {
    let outputs = [
        ("png", "PNG", true, false, true),
        ("jpeg", "JPEG", false, true, true),
        ("webp", "WebP", true, false, true),
        ("gif", "GIF", true, true, false),
        ("tiff", "TIFF", true, false, false),
        ("bmp", "BMP", true, false, false),
        ("ico", "ICO", true, false, false),
        ("tga", "TGA", true, false, false),
        ("qoi", "QOI", true, false, false),
        ("pnm", "PNM", false, false, false),
        ("farbfeld", "Farbfeld", true, false, false),
    ];

    let outputs_json: Vec<String> = outputs
        .iter()
        .map(|(id, label, alpha, lossy, common)| {
            format!(
                "{{\"id\":\"{id}\",\"label\":\"{label}\",\"alpha\":{alpha},\"lossy\":{lossy},\"common\":{common}}}"
            )
        })
        .collect();

    let inputs_json: Vec<String> = codec::INPUT_FORMATS
        .iter()
        .map(|f| format!("\"{f}\""))
        .collect();

    let filters = [
        "nearest",
        "box",
        "bilinear",
        "hamming",
        "catmullrom",
        "mitchell",
        "lanczos3",
    ];
    let filters_json: Vec<String> = filters.iter().map(|f| format!("\"{f}\"")).collect();

    format!(
        "{{\"inputs\":[{}],\"outputs\":[{}],\"filters\":[{}],\"simd\":{},\"version\":\"{}\"}}",
        inputs_json.join(","),
        outputs_json.join(","),
        filters_json.join(","),
        cfg!(target_feature = "simd128"),
        env!("CARGO_PKG_VERSION"),
    )
}
