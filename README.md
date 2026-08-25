# A10city Image Editor

Convert, resize, crop, straighten and adjust images **entirely in the browser**.
The engine is Rust compiled to WebAssembly; the picture you drop in is decoded,
edited and re-encoded inside the tab and never touches a server.

**Live:** [a10city.com/editor](https://a10city.com/editor)

```
  your file ──▶ Rust/WASM worker ──▶ your download
                       ▲
             nothing crosses the network
```

---

## What it does

| | |
|---|---|
| **Convert** | Read PNG · JPEG · WebP · GIF · TIFF · BMP · ICO · TGA · QOI · PNM · HDR · Farbfeld (plus AVIF/HEIC/SVG via the browser's own decoders). Write PNG · JPEG · WebP · GIF · TIFF · BMP · ICO · TGA · QOI · PNM · Farbfeld. |
| **Resize** | Any dimensions, with or without aspect lock, across seven resampling kernels from Nearest to Lanczos-3. |
| **Crop** | Drag a selection on the preview, with rule-of-thirds guides, eight resize handles, ratio presets (1:1, 4:3, 16:9, 3:4, 9:16), keyboard nudging, and exact pixel fields. |
| **Rotate** | Lossless 90° turns and mirror flips, plus a free straighten dial that expands the canvas instead of clipping the corners. |
| **Adjust** | Brightness, contrast, saturation, unsharp mask, Gaussian blur, grayscale, invert. |

Extras that matter in practice: EXIF orientation is honoured so phone photos
open upright, alpha is premultiplied around every resample so cut-outs do not
get dark fringes, formats without an alpha channel are flattened onto a matte
colour you choose, and holding **Original** shows the untouched image for
comparison.

Keyboard: `R` / `Shift+R` rotate, `H` / `V` flip, `C` toggles the crop tool,
arrow keys nudge a selection (`Shift` for 10px), `Esc` clears it.

---

## Why these libraries

The brief asked for OpenCV bindings where required. **They are not usable here,
and nothing in this editor requires them.** The `opencv` crate binds to a native
OpenCV build through libclang; it does not support `wasm32-unknown-unknown`, and
getting OpenCV into a browser at all means Emscripten and `opencv.js` — a
separate toolchain that does not interoperate with `wasm-bindgen`, and several
megabytes of payload for operations that are a few hundred lines of Rust.

So the engine uses the fastest pure-Rust equivalents, each chosen for a specific
reason:

| Crate | Role | Why this one |
|---|---|---|
| [`image`](https://crates.io/crates/image) | Decode and encode | One dependency covers every popular container. Avoids a pile of C libraries that would not cross-compile. |
| [`fast_image_resize`](https://crates.io/crates/fast_image_resize) | Resampling | The single biggest performance lever here. Its convolution kernels are hand-vectorised for WebAssembly `simd128`, several times faster than a scalar resize, and it handles alpha premultiplication correctly. |
| [`imageproc`](https://crates.io/crates/imageproc) | Affine warp, Gaussian | The pure-Rust stand-in for the OpenCV routines — `warpAffine` and `GaussianBlur` equivalents that actually compile to wasm. |

The build enables `simd128` (`.cargo/config.toml`), supported by Chrome 91+,
Firefox 89+ and Safari 16.4+. The footer of the running app reports whether the
SIMD path is live.

**Known limits.** WebP is written losslessly — a lossy WebP encoder means
linking libwebp through C, which this target cannot do. AVIF, HEIC and SVG are
read through the browser's decoders rather than shipping another megabyte of
WebAssembly, and cannot be written. ICO is capped at 256×256 by the format.

---

## How it is put together

```
crates/imagecore/          the Rust engine
  src/codec.rs             decode/encode, EXIF orientation, alpha flattening
  src/ops.rs               resampling, affine warp, tonal operators
  src/pipeline.rs          the edit pipeline and its resolution cache
  src/lib.rs               the wasm-bindgen surface
  tests/pipeline.rs        38 behavioural tests, run natively

src/                       the web app
  worker.ts                hosts the engine off the main thread
  engine.ts                request correlation and preview coalescing
  crop.ts                  the interactive selection
  main.ts                  control wiring
  style.css                the A10city brand kit
  editor.css               editor components
```

### Edits are declarative, and replayed

The UI never mutates pixels. It holds one JSON `Pipeline` and asks the worker to
replay it against the pristine decoded source:

```
source ▸ flip ▸ quarter turns ▸ free rotate ▸ crop ▸ resize ▸ adjust
                                            └──────┘
                                        "crop space" — the frame
                                        crop rectangles are measured in
```

Two consequences worth knowing:

- **No accumulated resampling error.** Dragging the straighten dial after a
  resize does not stack interpolation on interpolation; there is exactly one
  resample between the original pixels and what you see.
- **Crop comes after rotation.** Straightening a photo and then trimming the
  transparent wedges is the whole point of a free rotation, and it means a crop
  rectangle lives in the coordinates you are actually looking at.

Rotation by an exact multiple of 90° is folded into the lossless quarter-turn
path rather than going through the resampler.

### Three things keep it responsive

A 24-megapixel photo is a lot of pixels to touch on every frame of a slider
drag. Measured on a 6000×4000 source, straighten previews went from **391 ms to
81 ms** through:

1. **Shedding resolution before the expensive operators.** A 24MP source
   downsampled to a 900px preview does not need 24MP of warping to look
   identical, so the reduction happens before the warp and the Gaussian.
2. **Caching that reduction, on a halving ladder.** Redoing the reduction every
   frame cost more than everything else combined. Reductions are restricted to
   successive halvings, which are both the highest-quality box reductions
   available and — more importantly — a stable cache key: a straighten drag
   grows the working frame slightly each frame and would miss a cache keyed on
   exact dimensions. `tests/pipeline.rs` asserts a warm cache renders
   bit-identically to a cold one.
3. **Bilinear warps for previews, bicubic for exports.** On an image already
   reduced for the screen the difference is invisible and it is roughly three
   times faster. Exports always use the full-resolution source and the better
   kernel.

Previews also coalesce: while one frame renders, newer requests replace each
other rather than queueing, so a slider drag costs one render per frame the
engine can actually deliver.

---

## Development

Requires Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, and Node 22.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

npm install
npm run dev        # builds the engine, then serves with hot reload
```

| Command | |
|---|---|
| `npm run dev` | Build the engine and serve locally |
| `npm run build` | Production build into `dist/` |
| `npm run build:wasm` | Rebuild only the WebAssembly engine |
| `npm test` | Run the engine's test suite |
| `npm run typecheck` | Type-check the web app |

`src/wasm/` is build output and is not committed; `npm run dev` and
`npm run build` regenerate it.

Pushes to `main` deploy to GitHub Pages via `.github/workflows/deploy.yml`.
Pull requests run formatting, Clippy, the test suite, a WebAssembly build and a
full site build via `.github/workflows/ci.yml`.

---

## Privacy

There is no upload endpoint, because there is no server side. Images are
decoded, edited and encoded in a Web Worker in your own tab. The only network
requests the page makes are for its own assets, Google Fonts, and A10city's
privacy-first analytics — none of which sees your image.

---

© A10city Private Limited · [info@a10city.com](mailto:info@a10city.com)
