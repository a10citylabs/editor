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

pub mod c2pa;
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
    Credentials(String),
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
            Self::Credentials(m) => write!(f, "Content Credentials: {m}"),
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
    /// Content Credentials found in the file that was opened, already
    /// validated. Only the manifest store is kept, not the source file: the
    /// store is a few kilobytes and is all a new manifest needs to carry the
    /// provenance chain forward.
    credentials: Option<c2pa::ValidationReport>,
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

        // Read any Content Credentials while the encoded bytes are still to
        // hand - the hard binding is over those bytes, so it cannot be checked
        // once the file has been decoded to pixels. A malformed manifest is
        // reported as "none found" rather than failing the open: a broken
        // credential is no reason to refuse to edit someone's photo.
        let credentials = if c2pa::supports_format(&decoded.format) {
            c2pa::read_jpeg(bytes).ok().flatten()
        } else {
            None
        };

        Ok(Editor {
            source: SourceCache::new(decoded.image),
            source_format: decoded.format,
            had_alpha: decoded.had_alpha,
            credentials,
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
            // Raw pixels arrive already decoded by the browser, so whatever
            // container they came from is gone and there is nothing to read.
            credentials: None,
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

    /// What the file that was opened carries, as JSON, or `None` when it has no
    /// Content Credentials. See `c2pa::ValidationReport`.
    #[wasm_bindgen(getter, js_name = credentials)]
    pub fn credentials(&self) -> Option<String> {
        self.credentials
            .as_ref()
            .map(c2pa::ValidationReport::to_json)
    }

    /// The thumbnail from the opened file's active manifest, if it has one.
    /// Handed over as JPEG bytes for the host to turn into a Blob.
    #[wasm_bindgen(js_name = credentialThumbnail)]
    pub fn credential_thumbnail(&self) -> Option<Vec<u8>> {
        self.credentials
            .as_ref()
            .and_then(|report| report.active.thumbnail.clone())
    }

    /// Compose at full resolution and encode. `encode_json` accepts
    /// `{"format":"jpeg","quality":85,"pngCompression":"default","background":[255,255,255]}`.
    ///
    /// `sign_json` requests Content Credentials. Empty means "do not sign";
    /// otherwise it is a [`SignOptions`], and the caller supplies the clock and
    /// the randomness because WebAssembly has neither.
    #[wasm_bindgen(js_name = renderExport)]
    pub fn render_export(
        &mut self,
        pipeline_json: &str,
        encode_json: &str,
        sign_json: &str,
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
        let mut bytes = codec::encode(&rendered.image, format, &opts)?;

        let mut manifest_bytes = 0u32;
        if !sign_json.trim().is_empty() {
            let options: SignOptions =
                serde_json::from_str(sign_json).map_err(|e| Error::Credentials(e.to_string()))?;

            // Refusing rather than silently skipping. The caller only sets this
            // when the user asked for a credential, and quietly handing back an
            // unsigned file would be the one failure mode worth avoiding.
            if !c2pa::supports_format(&request.format) {
                return Err(Error::Credentials(format!(
                    "Content Credentials can only be written to JPEG, not {}",
                    request.format
                ))
                .into());
            }

            let signed = self.sign(&bytes, &pipeline, (width, height), &options)?;
            manifest_bytes = u32::try_from(signed.embedded_len).unwrap_or(u32::MAX);
            bytes = signed.jpeg;
        }

        Ok(ExportResult {
            width,
            height,
            mime: format.mime().to_string(),
            extension: format.extension().to_string(),
            bytes,
            manifest_bytes,
        })
    }

    /// Attach a manifest to freshly encoded JPEG bytes.
    fn sign(
        &mut self,
        jpeg: &[u8],
        pipeline: &Pipeline,
        output: (u32, u32),
        options: &SignOptions,
    ) -> Result<c2pa::Signed, Error> {
        // Something was opened in every case the editor supports - there is no
        // "File > New" here - so the first action is always c2pa.opened and
        // there is always a parentOf ingredient to point it at.
        let actions = c2pa::actions_for(pipeline, true, output);

        let parent = c2pa::Parent {
            title: options.source_name.clone(),
            format: options.source_mime.clone(),
            instance_id: options.source_instance_id.clone(),
            store: self.credentials.as_ref().map(|report| c2pa::ParentStore {
                bytes: report.store.clone(),
                active_manifest: report.active.label.clone(),
                status: report.active.status.clone(),
            }),
        };

        let thumbnail = if options.thumbnail {
            self.thumbnail(pipeline)
        } else {
            None
        };

        let request = c2pa::SignRequest {
            title: options.title.clone(),
            generator: c2pa::generator(),
            now: options.now.clone(),
            instance_id: options.instance_id.clone(),
            manifest_id: options.manifest_id.clone(),
            actions,
            parent: Some(parent),
            thumbnail,
        };

        c2pa::sign_jpeg(jpeg, &request).map_err(Error::Credentials)
    }

    /// A small JPEG of the finished image for the `c2pa.thumbnail.claim`
    /// assertion, so a viewer can show what was signed without decoding the
    /// whole file. Failure here is not worth failing an export over - the
    /// thumbnail is a convenience, not part of the binding.
    fn thumbnail(&mut self, pipeline: &Pipeline) -> Option<Vec<u8>> {
        // Rendering through the shared cache rather than a copy: the reduction
        // ladder is already warm from the last preview, so a thumbnail costs
        // almost nothing on top of the export that just ran.
        let rendered = pipeline::render(
            &mut self.source,
            pipeline,
            Target::Preview {
                max_width: THUMBNAIL_MAX,
                max_height: THUMBNAIL_MAX,
            },
        )
        .ok()?;

        codec::encode(
            &rendered.image,
            OutputFormat::Jpeg,
            &EncodeOptions {
                quality: 70,
                png_compression: "default".to_string(),
                background: [255, 255, 255],
            },
        )
        .ok()
    }
}

/// Longest edge of the thumbnail embedded in a manifest. Large enough to
/// recognise the picture, small enough not to dominate the manifest.
const THUMBNAIL_MAX: u32 = 256;

/// What the host must supply to sign, since WebAssembly has neither a clock nor
/// a random number generator. The browser has both, and passing them in also
/// keeps signing reproducible for tests.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignOptions {
    /// `dc:title` for the output.
    title: String,
    /// RFC 3339 timestamp for every action's `when`.
    now: String,
    /// `xmpMM:InstanceID` of the output, from `crypto.randomUUID()`.
    instance_id: String,
    /// `urn:c2pa:<uuid>` label for the new manifest.
    manifest_id: String,
    /// Name of the file that was opened, for the ingredient assertion.
    #[serde(default)]
    source_name: String,
    #[serde(default = "default_source_mime")]
    source_mime: String,
    #[serde(default)]
    source_instance_id: String,
    #[serde(default)]
    thumbnail: bool,
}

fn default_source_mime() -> String {
    "image/jpeg".to_string()
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
    manifest_bytes: u32,
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
    /// Bytes the Content Credential added to the file, or 0 if unsigned.
    #[wasm_bindgen(getter, js_name = manifestBytes)]
    pub fn manifest_bytes(&self) -> u32 {
        self.manifest_bytes
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
        "{{\"inputs\":[{}],\"outputs\":[{}],\"filters\":[{}],\"simd\":{},\"version\":\"{}\",\"contentCredentials\":{}}}",
        inputs_json.join(","),
        outputs_json.join(","),
        filters_json.join(","),
        cfg!(target_feature = "simd128"),
        env!("CARGO_PKG_VERSION"),
        content_credentials_json(),
    )
}

/// What this build can do with Content Credentials, and who it signs as.
///
/// The `untrusted` flag is not decoration. A browser claim generator publishes
/// its signing key by existing, so the identity in every credential it writes
/// is unverifiable, and the interface has to say so rather than showing a green
/// tick. See `signing/README.md`.
fn content_credentials_json() -> String {
    let Ok(signer) = c2pa::signer::describe() else {
        return "{\"available\":false}".to_string();
    };

    let escape = |value: &str| value.replace('\\', "\\\\").replace('"', "\\\"");
    let usages: Vec<String> = signer
        .extended_key_usage
        .iter()
        .map(|eku| format!("\"{}\"", escape(eku)))
        .collect();

    format!(
        "{{\"available\":true,\"formats\":[\"jpeg\"],\"signer\":{{\
         \"name\":\"{}\",\"organisation\":\"{}\",\"issuer\":\"{}\",\
         \"expires\":\"{}\",\"algorithm\":\"ES256\",\"keyUsage\":[{}],\
         \"untrusted\":{},\"timeStamped\":false,\"source\":\"{}\"}}}}",
        escape(&signer.common_name),
        escape(&signer.organisation),
        escape(&signer.issuer),
        escape(&signer.not_after),
        usages.join(","),
        signer.anchor_is_self_signed,
        signer.credential_source,
    )
}
