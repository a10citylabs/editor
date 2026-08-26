# A10city Image Editor

Convert, resize, crop, straighten and adjust images **entirely in the browser**.
The engine is Rust compiled to WebAssembly; the picture you drop in is decoded,
edited and re-encoded inside the tab and never touches a server.

JPEGs also get **C2PA Content Credentials**: the editor checks any credential
already in the file, and can sign what it exports with a manifest recording
every edit it made. That happens in the tab too — there is no signing service.

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
| **Attest** | Read and verify C2PA Content Credentials on JPEG input; write a signed manifest on JPEG output recording what was done. Other formats are untouched — see [Content Credentials](#content-credentials). |

Extras that matter in practice: EXIF orientation is honoured so phone photos
open upright, alpha is premultiplied around every resample so cut-outs do not
get dark fringes, formats without an alpha channel are flattened onto a matte
colour you choose, and holding **Original** shows the untouched image for
comparison.

Keyboard: `R` / `Shift+R` rotate, `H` / `V` flip, `C` toggles the crop tool,
arrow keys nudge a selection (`Shift` for 10px), `Esc` clears it.

---

## Content Credentials

[C2PA](https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html)
Content Credentials attach a signed, tamper-evident record of an image's history
to the image itself. This editor is a working **claim generator** and
**validator** for them, built against the 2.2 specification, running entirely in
the browser.

Open a JPEG and the panel says whether it carries a credential and whether that
credential holds up. Export a JPEG and — if you leave the switch on — it gets a
new manifest naming every operation the editor performed, with the previous
credential carried forward as a `parentOf` ingredient so the chain of custody
survives the edit.

### Scope

**JPEG in, JPEG out.** The hard binding written here is `c2pa.hash.data`, which
commits to a byte range of the finished file, so both embedding and the
exclusion rules have to be written per container format (§18.5.3 covers JPEG,
§18.5.4 PNG, and so on). JPEG's `APP11` segments are the case the specification
treats in most detail and what most C2PA tooling reads today.

Everything else works exactly as before. Open a PNG and the editor edits a PNG;
the panel says credentials are read from JPEG rather than implying the file was
checked and came up clean. Export to WebP and the switch greys out with the
reason next to it. Nothing is silently dropped: asking for a credential on a
non-JPEG export is an error, not a no-op.

### What is in a manifest it writes

```
c2pa                                  manifest store
├── urn:c2pa:<uuid>                   an inherited manifest, if the input had one
└── urn:c2pa:<uuid>                   the active manifest
    ├── c2pa.assertions
    │   ├── c2pa.thumbnail.claim      256px JPEG of the result (bfdb + bidb)
    │   ├── c2pa.ingredient.v3        the opened file, relationship parentOf
    │   ├── c2pa.actions.v2           one action per operation performed
    │   └── c2pa.hash.data            hard binding, excluding the manifest itself
    ├── c2pa.claim.v2                 deterministic CBOR, hashes every assertion
    └── c2pa.signature                COSE_Sign1, ES256, detached payload
```

The actions assertion is the part that carries meaning. A manifest that says
`c2pa.edited` and stops is valid and useless; this one maps each pipeline
operation onto the predefined action that fits it, with the specifics attached:

| You did | It records |
|---|---|
| Opened a file | `c2pa.opened`, pointing at the ingredient assertion |
| Rotate / flip | `c2pa.orientation` — "rotated 90°, flipped horizontally" |
| Straighten | a second `c2pa.orientation` — a free rotation resamples, a quarter turn does not |
| Crop | `c2pa.cropped` — "cropped to 160x120 at (8, 12)" |
| Resize | `c2pa.resized` — "resized to 80x60" |
| Brightness / contrast / saturation / grayscale / invert | `c2pa.adjustedColor` |
| Sharpen | `c2pa.enhanced` (a non-editorial transformation, in C2PA's vocabulary) |
| Blur | `c2pa.filtered` |

Entity-specific parameters are namespaced `com.a10city.*` as §6.2.1 requires.
`allActionsIncluded` is set, which asserts nothing happened off the record — the
editor knows every operation it performed, so it can say so.

### The circular dependency

The hard binding hashes the finished file, but the manifest lives inside that
file and its size is not known until it is built — which cannot happen until the
hash exists. §10.4 breaks the loop with fixed-width placeholders, and
`manifest.rs` does it in two renders: once with a zeroed hash, a zeroed
signature and a `(0, 0)` exclusion to measure the result, then again with the
real values substituted in. It works because every placeholder is exactly as
wide as the value replacing it — SHA-256 is always 32 bytes, an ES256 signature
always 64, and the exclusion offsets are written as 32-bit integers whatever
their value, which is what §18.5.2 asks for. The two lengths are asserted equal
rather than assumed.

### Verified against the reference implementation

Files this editor produces are read and validated by
[`c2patool`](https://github.com/contentauth/c2pa-rs), the reference
implementation:

```
$ c2patool signed.jpg
validation_state : Valid
success          : assertion.dataHash.match, assertion.hashedURI.match,
                   claimSignature.insideValidity, claimSignature.validated
failure          : signingCredential.untrusted
```

That last line is the honest one, and the next section is about it. Tamper with
a signed file and both this validator and `c2patool` return
`assertion.dataHash.mismatch`.

### What a credential from this app does and does not prove

A C2PA manifest supports two quite different claims, and only one of them
survives here.

**It does prove integrity.** The pixels have not changed since signing — that is
the hard binding, and it is real. Alter one byte of image data and validation
fails, in this app and in every other C2PA tool.

**It does not prove identity.** The signing key is compiled into a WebAssembly
module that is served to every visitor, so anyone can read it out and mint a
manifest bearing this signer's name. There is no arrangement in which a purely
client-side claim generator holds a secret key; that is a property of signing in
the browser, not a shortcut taken here.

So the app never shows a tick beside a signer. It reports the two claims as two
separate lines — integrity in green, identity as plain text naming who has
vouched for the signer, which is nobody — and names the specification status
code for every check so a reader can see exactly which guarantee they are being
given. `signingCredential.untrusted` is displayed, not hidden.

**On GitHub secrets:** they cannot make a browser-side key secret. A secret is
decrypted in the Actions runner, and whatever the runner bakes into `dist/` is
downloadable. They are wired up anyway for the one real thing they buy — keeping
a key out of public git history — so a fork can deploy under its own rotatable
key by setting `C2PA_SIGNING_CERT` and `C2PA_SIGNING_KEY`. Without them the
committed demo key is used, so a fresh clone builds and signs with no setup.
[`signing/README.md`](signing/README.md) works through the reasoning and sketches
the two designs — remote signing over a hash, or per-user certificates — that
would produce credentials worth trusting without giving up the no-upload
property.

### Not implemented, and why

- **RFC 3161 time-stamps** (§10.3.2.5) and **stapled OCSP responses**
  (§10.3.2.6). Both need a network round-trip to a third party while signing,
  which an app whose premise is that nothing leaves the tab cannot make. Their
  absence is reported in the UI rather than glossed over. It has a real cost: a
  manifest without a time-stamp stops validating when its signing certificate
  expires, which is why the demo certificate is dated twenty years out.
- **Trust-list checking.** Deciding whether a signer is trustworthy needs a
  trust anchor store; the app reports what a certificate says about itself and
  states plainly that nothing has been checked against any list.
- **Assertion salts** (`c2sh`), which matter for redaction. Boxes that arrive
  carrying one are preserved byte-for-byte so they still hash correctly.
- **Formats other than JPEG**, per the scope note above.

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
| [`p256`](https://crates.io/crates/p256) + [`sha2`](https://crates.io/crates/sha2) | ES256 signatures, hashing | The only two crates the C2PA layer needs. `c2pa-rs` was the obvious alternative and is the wrong shape here: it carries a trust-list and OCSP stack this has no use for, and its wasm story goes through a different toolchain than `wasm-bindgen`. The CBOR, JUMBF and COSE layers are written against the specification instead, which is a few hundred readable lines and keeps the module small. |

The build enables `simd128` (`.cargo/config.toml`), supported by Chrome 91+,
Firefox 89+ and Safari 16.4+. The footer of the running app reports whether the
SIMD path is live.

One trap worth naming, because it is the usual way crypto crates fail to reach
`wasm32-unknown-unknown`: that target has no clock and no random number
generator, and `getrandom` 0.2 will not compile for it without a JavaScript
shim. `p256` pulls `getrandom` in transitively through its `std` feature, so
that feature is off. Nothing here needs it — ECDSA signing is deterministic per
RFC 6979, and the timestamps and UUIDs are passed in from the host, which also
makes every signing test reproducible.

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
  src/c2pa/                the C2PA claim generator and validator
    cbor.rs                deterministic CBOR (RFC 8949 §4.2.1)
    jumbf.rs               JUMBF boxes (ISO/IEC 19566-5)
    jpegxt.rs              APP11 embedding and the hard-binding exclusions
    x509.rs                enough DER to read a signing certificate
    cose.rs                COSE_Sign1 over the claim (RFC 8152, RFC 9360)
    signer.rs              the build's key material
    manifest.rs            claims, assertions and validation
  build.rs                 compiles the signing credentials in
  tests/pipeline.rs        38 behavioural tests, run natively
  tests/c2pa.rs            15 end-to-end signing and tamper tests

signing/                   the demo signing chain, and why it is public

src/                       the web app
  worker.ts                hosts the engine off the main thread
  engine.ts                request correlation and preview coalescing
  crop.ts                  the interactive selection
  credentials.ts           the Content Credentials panel
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
| `./signing/generate.sh` | Regenerate the demo signing chain |

To check the credentials against something other than this code, install the
reference tool and point it at a JPEG the app exported:

```sh
cargo install c2patool
c2patool ~/Downloads/photo-edited.jpg
```

Expect `"validation_state": "Valid"` with `signingCredential.untrusted` as the
only failure — see [Content Credentials](#content-credentials) for why that is
the correct result rather than a bug.

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

Signing does not change that. The manifest is built and signed in the same
worker, with a key compiled into the WebAssembly module, so a Content Credential
costs no network request either. The trade is the one described above: a key
that lives in the browser is a key everyone has, so these credentials prove that
an image is unaltered and not who made it.

Note that a credential is *content* — the actions assertion records what you did
to the picture, and the ingredient assertion records the filename you opened.
That travels with the file wherever you send it. The switch is there to turn
off.

---

© A10city Private Limited · [info@a10city.com](mailto:info@a10city.com)
