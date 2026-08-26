# A10city Image Editor

Convert, resize, crop, straighten and adjust images **entirely in the browser**.
The engine is Rust compiled to WebAssembly; the picture you drop in is decoded,
edited and re-encoded inside the tab and never touches a server.

JPEGs also get **C2PA Content Credentials**: the editor checks any credential
already in the file, and can sign what it exports with a manifest recording
every edit it made.

Signing the *claim* happens on a small service, because the C2PA Conformance
Program requires the signing key to be somewhere a browser cannot be. The
picture is still never uploaded — what crosses the network is about a kilobyte
of claim, and never a pixel. [Why, in one paragraph](#the-signing-key-is-not-in-your-browser).

**Live:** [a10city.com/editor](https://a10city.com/editor)

```
  your file ──▶ Rust/WASM worker ──▶ your download
                       │      ▲
                       │      │  the image never leaves the tab
                       │      │
                 claim │      │ signature      (only when you ask for
                       └──────┘                 Content Credentials)
                     claim-signer
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
| **Attest** | Validate C2PA Content Credentials on JPEG input, against a trust list where one is configured; write a signed, time-stamped manifest on JPEG output recording what was done. Other formats are untouched — see [Content Credentials](#content-credentials). |

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
**validator** for them, built against the 2.2 specification, and shaped to pass
the [C2PA Conformance Program][program] at Assurance Level 1 — see
[`conformance/`](conformance/README.md) for the evidence and what is still
outstanding.

[program]: https://github.com/c2pa-org/conformance-public

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
                   claimSignature.insideValidity, claimSignature.validated,
                   signingCredential.trusted, timeStamp.validated
```

Tamper with a signed file and both this validator and `c2patool` return
`assertion.dataHash.mismatch`.

The same validator, driven from the command line, produces
[crJSON](https://spec.c2pa.org/specifications/specifications/2.4/crJSON/crjson-format.html) —
the format the Conformance Program asks applicants to submit:

```sh
c2pa-harness validate --asset signed.jpg \
    --trust-list c2pa-trust-list.pem \
    --tsa-trust-list c2pa-tsa-trust-list.pem \
    --validation-time 2026-08-27T08:30:12Z
```

Those four flags are exactly the four inputs the Program specifies. It is a
front end over the code the browser runs, not a second implementation that could
quietly disagree with it.

### The signing key is not in your browser

An earlier version of this editor compiled a signing key into the WebAssembly
module. It was honest about the consequence — the interface said the identity
was unverifiable, because anyone who loads the page can read the key out — but
honesty is not conformance.

Objective **O.2** of the [C2PA Generator Product Security Requirements][gpsr]
asks for a claim signing key that is encrypted at rest, encrypted in memory
except while signing, access-controlled by least privilege, and rotatable. A key
served to every visitor fails all four, and the failure is not a matter of
degree: it put Assurance Level 1 — and therefore the Conforming Products List,
and therefore any certificate a validator would recognise — permanently out of
reach.

[gpsr]: https://github.com/c2pa-org/conformance-public/tree/main/docs/v0.2

So the key moved to [`services/claim-signer`](services/claim-signer/README.md),
and the product became a **Distributed** implementation in the Program's terms:

```text
 Edge (your browser)                        Backend (claim-signer)
 ───────────────────                        ──────────────────────────────
 decode, edit, encode                       the only claim signing key
 build the assertions and the claim         AES-256-GCM at rest, zeroised
 compute the Sig_structure   ── TLS 1.3 ──▶ after each use
 (~1 KB: no pixels)                         sign, then fetch a time-stamp
 assemble and embed          ◀────────────  signature + TimeStampToken
```

The no-upload promise is unchanged, and it is now enforced rather than asserted:
`conformance/scripts/check-no-key-material.sh` fails the build if the shipped
`.wasm` contains a PEM private-key header, the bytes of the test key, or so much
as a dependency edge on a private-key parser. It runs in CI and again before
every deployment.

Without a configured signer — which is the case on the plain GitHub Pages build,
where there is no application server to mint a session credential — the editor
works exactly as it always did and exports without a credential, and says so.
There is no half-configured state and no button that fails.

### What a credential from this app proves

**Integrity.** The pixels have not changed since signing. That is the hard
binding, and it is real: alter one byte of image data and validation fails, here
and in every other C2PA tool.

**What was done, and by what.** One action per operation the user actually
performed, with the parameters that describe it, and `allActionsIncluded` set so
a reader knows the list is complete. Every editing action carries the IPTC
source type `humanEdits` — "augmentation, correction or enhancement by one or
more humans using non-generative tools" — because that is exactly what this
editor is. Nothing generative is ever claimed, and a test asserts it.

**Identity — once there is a certificate.** The interface distinguishes three
states rather than two, because they are genuinely different:

| | Shown as |
|---|---|
| The chain reached an anchor on the configured trust list | the anchor's name |
| A trust list was configured and the chain missed it | *not on the trust list* |
| No trust list was configured | *not checked against any trust list* |

Collapsing the middle case into either of the others is the failure C2PA exists
to prevent — someone believing a picture because an interface told them to, or
dismissing a good one because it said the wrong thing.

Where the certificate carries them, the Assurance Level and the Conforming
Products List record id are shown too, straight from the `c2pa-al` and
`c2pa-cpl-record` extensions. Those two facts are what separate a conformant
Generator Product from anything that can emit CBOR.

### Time-stamps, and why they are not optional

A C2PA claim signing certificate at Assurance Level 1 is capped at **366 days**.
§15.8 judges an untimestamped manifest against the validity window *at the
moment someone looks at it* — so without a time-stamp, every image this editor
has ever signed would stop validating on the certificate's anniversary.

With one, a validator judges the certificate at the attested time instead, and
the credential stays good indefinitely. The Backend asks an RFC 3161 authority
for a stamp over each signature (a 32-byte digest crosses that hop and nothing
else), and the manifest reserves space for the token before it exists —
`pad` and `pad2` in the COSE unprotected header, exactly as §10.4.2 and §10.4.4
prescribe, shrunk to the byte once the real token arrives.

When the authority is unreachable the file is still written, the interface says
why there is no stamp, and the credential is valid until the certificate
expires. Refusing to save someone's photograph because a third party was down
would be the wrong trade.

### Still not implemented, and why

- **Stapled OCSP responses** (§10.3.2.6). Revocation status is reported as
  `signingCredential.ocsp.skipped` rather than assumed either way. The Backend
  is the right place to capture one, and it is the obvious next addition.
- **Assertion salts** (`c2sh`), which matter for redaction. Boxes that arrive
  carrying one are preserved byte-for-byte so they still hash correctly.
- **Ed25519 and P-521 signatures.** Both are on the specification's allowed
  list; the validator reports them as *unsupported* rather than as invalid,
  because a validator that says "this does not verify" when it means "I cannot
  check this" is worse than one that admits the gap.
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

The layout follows the Target of Evaluation boundary the C2PA Conformance
Program cares about: what runs in the browser, what runs on a server, and what
is evidence about the two.

```
apps/editor/               the Edge subsystem: the browser application
  index.html
  src/worker.ts            hosts the engine off the main thread, and drives signing
  src/engine.ts            request correlation and preview coalescing
  src/signer.ts            the claim-signer client (HMAC, identity, sign)
  src/crop.ts              the interactive selection
  src/credentials.ts       the Content Credentials panel
  src/main.ts              control wiring
  src/style.css            the A10city brand kit
  src/editor.css           editor components

crates/imagecore/          the Edge engine. No key material, by construction
  src/codec.rs             decode/encode, EXIF orientation, alpha flattening
  src/ops.rs               resampling, affine warp, tonal operators
  src/pipeline.rs          the edit pipeline and its resolution cache
  src/lib.rs               the wasm-bindgen surface
  src/c2pa/                the C2PA claim generator and validator
    cbor.rs                deterministic CBOR (RFC 8949 §4.2.1)
    clock.rs               RFC 3339 and ASN.1 times as comparable instants
    der.rs                 a small DER writer, for RFC 3161 requests
    jumbf.rs               JUMBF boxes (ISO/IEC 19566-5)
    jpegxt.rs              APP11 embedding and the hard-binding exclusions
    x509.rs                RFC 5280, plus the C2PA Certificate Policy extensions
    verify.rs              signature checking for every algorithm §13.2.1 allows
    trust.rs               path validation against a C2PA Trust List
    timestamp.rs           RFC 3161 tokens and §15.8 validation
    identity.rs            the public half of the signing credential
    cose.rs                COSE_Sign1, padding and sigTst2 (RFC 8152, RFC 9360)
    manifest.rs            claims, assertions, prepare/complete, validation
    crjson.rs              the crJSON serialisation of a validation result
    testpki.rs             test fixtures, behind a feature no release enables
  tests/pipeline.rs        38 behavioural tests, run natively
  tests/c2pa.rs            28 end-to-end signing, trust and tamper tests
  tests/evidence.rs        writes the conformance sample assets

crates/c2pa-harness/       the conformance test harness: asset in, crJSON out

services/claim-signer/     the Backend subsystem: the only place a key exists
  src/keystore.rs          sealed key storage, ephemeral use, rotation
  src/auth.rs              authenticating the Edge (O.2)
  src/tsa.rs               the RFC 3161 client
  src/main.rs              TLS 1.3, routing, the signing endpoint

conformance/               the evidence, and how to reproduce it
  generator-product-security-architecture.md
  requirements-matrix.md   every Level 1 requirement, and where it is met
  enrolment-runbook.md     how to get a real certificate
  test-credentials/        a test PKI shaped like the real thing
  scripts/                 SBOM, the 90-day gate, the no-key check, evidence
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
| `npm test` | Run the whole Rust workspace's test suite |
| `npm run typecheck` | Type-check the web app |
| `npm run sbom` | Software Bill of Materials for every component |
| `npm run audit:supply-chain` | The 90-day CRITICAL/HIGH gate |
| `./conformance/scripts/generate-evidence.sh` | Sample assets and their crJSON |
| `./conformance/scripts/check-no-key-material.sh` | Prove the bundle holds no key |
| `./conformance/test-credentials/generate.sh` | Regenerate the test PKI |

### Running with a signer

The editor works without one — it just exports unsigned. To exercise the whole
path locally:

```sh
cargo run -p claim-signer -- import \
    --id dev --key conformance/test-credentials/c2pa-test-claim-signer.key \
    --chain conformance/test-credentials/c2pa-test-claim-signer-chain.pem
cargo run -p claim-signer -- activate --id dev
CLAIM_SIGNER_ALLOW_PLAINTEXT=1 cargo run -p claim-signer -- serve
```

with `CLAIM_SIGNER_KEYSTORE`, `CLAIM_SIGNER_KEK` and `CLAIM_SIGNER_CLIENTS` set
— see [`services/claim-signer/README.md`](services/claim-signer/README.md).
Then put a `claim-signer.json` in `apps/editor/public/`:

```json
{
  "url": "http://localhost:8443",
  "credential": { "keyId": "dev", "secret": "<the same base64 secret>" }
}
```

`CLAIM_SIGNER_ALLOW_PLAINTEXT` is a development-only escape hatch and logs a
warning naming the conformance objective it violates every time it starts.

To check the credentials against something other than this code, install the
reference tool and point it at a JPEG the app exported:

```sh
cargo install c2patool
c2patool ~/Downloads/photo-edited.jpg
```

Expect `"validation_state": "Valid"`. With the test PKI, `signingCredential.untrusted`
appears unless you also point `c2patool` at
`conformance/test-credentials/c2pa-test-trust-list.pem`; see
[Content Credentials](#content-credentials) for why that is
the correct result rather than a bug.

`apps/editor/src/wasm/` and `conformance/evidence/` are build output and are not
committed; `npm run dev`, `npm run build` and `generate-evidence.sh` regenerate
them.

Pushes to `main` deploy to GitHub Pages via `.github/workflows/deploy.yml`.
Pull requests run four jobs via `.github/workflows/ci.yml`: formatting, Clippy
and the workspace test suite; the conformance evidence; the SBOM and the 90-day
vulnerability gate; and a full site build. The deploy workflow re-runs the
vulnerability gate *before* building and the no-key-material check *after*,
because a gate that only advises is not a gate.

---

## Privacy

There is no upload endpoint, because there is no server side. Images are
decoded, edited and encoded in a Web Worker in your own tab. The only network
requests the page makes are for its own assets, Google Fonts, and A10city's
privacy-first analytics — none of which sees your image.

Signing changes it by about a kilobyte, in one direction, and only when you ask
for a credential. The worker builds the manifest and computes a `Sig_structure`
— the claim, the certificate chain and a context string — and sends *that* to
the claim-signer. The image is not in it, and a test asserts as much: no run of
image bytes appears in what is sent, and the whole payload is a fraction of the
file's size.

The signing service therefore learns that someone signed a claim, and what that
claim says. It never sees the picture. The time-stamping authority beyond it
sees less again: 32 bytes of digest.

This is the trade that buys a credential worth believing. The alternative — a
key in the page — costs no network request at all and proves nothing about who
made the image, because everyone who loads the page has the key.

Note that a credential is *content* — the actions assertion records what you did
to the picture, and the ingredient assertion records the filename you opened.
That travels with the file wherever you send it. The switch is there to turn
off.

---

© A10city Private Limited · [info@a10city.com](mailto:info@a10city.com)
