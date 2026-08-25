/**
 * The wire format shared between the UI and the WebAssembly worker.
 *
 * These mirror the `serde` structs in `crates/imagecore/src/pipeline.rs`, so
 * the field names are the camelCase ones Rust expects. Keep the two in step.
 */

export interface CropRect {
    x: number;
    y: number;
    width: number;
    height: number;
}

export type ResampleFilter =
    | 'nearest'
    | 'box'
    | 'bilinear'
    | 'hamming'
    | 'catmullrom'
    | 'mitchell'
    | 'lanczos3';

export interface ResizeSpec {
    width: number;
    height: number;
    filter: ResampleFilter;
}

export interface AdjustSpec {
    brightness: number;
    contrast: number;
    saturation: number;
    grayscale: boolean;
    invert: boolean;
    /** Gaussian sigma in output pixels. */
    blur: number;
    /** Unsharp-mask amount. */
    sharpen: number;
}

export interface Pipeline {
    /** Rectangle in crop space: the frame after flips and rotation. */
    crop: CropRect | null;
    flipH: boolean;
    flipV: boolean;
    /** 90-degree clockwise steps, 0..=3. */
    quarterTurns: number;
    /** Free rotation in degrees clockwise. */
    angle: number;
    /** RGBA matte revealed by a free rotation. */
    background: [number, number, number, number];
    resize: ResizeSpec | null;
    adjust: AdjustSpec;
}

export interface EncodeSpec {
    format: string;
    quality: number;
    pngCompression: 'fast' | 'default' | 'best';
    /** RGB matte used when the target format has no alpha channel. */
    background: [number, number, number];
}

export interface OutputFormatInfo {
    id: string;
    label: string;
    /** Whether the container can carry an alpha channel. */
    alpha: boolean;
    /** Whether the quality slider does anything. */
    lossy: boolean;
    /** Whether to show it in the primary row rather than behind "more". */
    common: boolean;
}

export interface Capabilities {
    inputs: string[];
    outputs: OutputFormatInfo[];
    filters: ResampleFilter[];
    /** Whether this build has wasm SIMD enabled. */
    simd: boolean;
    version: string;
    contentCredentials: CredentialSupport;
}

/* -------------------------------------------------------------------------
   Content Credentials (C2PA)

   These mirror the report types in `crates/imagecore/src/c2pa/manifest.rs`.
   ------------------------------------------------------------------------- */

export interface CredentialSupport {
    /** False if this build has no usable signing key. */
    available: boolean;
    /** Output formats a manifest can be written to. JPEG only - see the
     *  module docs in `crates/imagecore/src/c2pa/mod.rs` for why. */
    formats?: string[];
    signer?: SignerInfo;
}

export interface SignerInfo {
    name: string;
    organisation: string;
    issuer: string;
    /** notAfter of the signing certificate, ISO-8601. */
    expires: string;
    algorithm: string;
    keyUsage: string[];
    /**
     * True when the chain ends in a self-signed root, i.e. nobody vouches for
     * this signer. Always true for a browser claim generator, whose key is
     * necessarily public. The UI must never present such a credential as
     * proving identity.
     */
    untrusted: boolean;
    /** Whether signatures carry an RFC 3161 time-stamp. Offline: never. */
    timeStamped: boolean;
    /** `repository` or `environment`, per `crates/imagecore/build.rs`. */
    source: string;
}

/** One entry of a `status-codes-map` (C2PA 2.2, section 15.2.1). */
export interface CredentialStatus {
    code: string;
    explanation: string;
}

export interface StatusCodes {
    success: CredentialStatus[];
    informational: CredentialStatus[];
    failure: CredentialStatus[];
}

export interface CredentialAction {
    /** A predefined name such as `c2pa.cropped`. */
    action: string;
    /** RFC 3339 timestamp. */
    when: string;
    description: string;
    softwareAgent: string;
}

export interface CredentialIngredient {
    title: string;
    format: string;
    /** `parentOf`, `componentOf` or `inputTo`. */
    relationship: string;
    hasManifest: boolean;
}

export interface CredentialSignature {
    algorithm: string;
    issuer: string;
    subject: string;
    subjectOrganisation: string;
    notBefore: string;
    notAfter: string;
    timeStamped: boolean;
}

export interface CredentialManifest {
    /** The `urn:c2pa:` label. */
    label: string;
    title: string;
    instanceId: string;
    generator: string;
    claimVersion: number;
    actions: CredentialAction[];
    ingredients: CredentialIngredient[];
    assertionLabels: string[];
    signature: CredentialSignature;
    status: StatusCodes;
}

export interface CredentialReport {
    /** The manifest describing the file as it is now. */
    active: CredentialManifest;
    /** Every manifest in the store, oldest first: the provenance chain. */
    chain: CredentialManifest[];
    /** Bytes the credential occupies in the file. */
    storeLen: number;
    /** True when every check that was applied passed. Says nothing about
     *  whether the signer should be trusted. */
    valid: boolean;
}

export interface SourceInfo {
    width: number;
    height: number;
    format: string;
    hasAlpha: boolean;
    /** Set when the browser decoded the file instead of the Rust engine. */
    viaBrowser: boolean;
    /** Content Credentials found in the opened file, already validated. */
    credentials: CredentialReport | null;
    /** Thumbnail from the credential's manifest, as an object URL. */
    credentialThumbnail: string | null;
}

export interface PreviewResult {
    pixels: ArrayBuffer;
    width: number;
    height: number;
    /** Resolution the export would land on. */
    outputWidth: number;
    outputHeight: number;
    /** Frame that crop rectangles are measured in. */
    cropSpaceWidth: number;
    cropSpaceHeight: number;
    ms: number;
}

export interface ExportPayload {
    bytes: ArrayBuffer;
    mime: string;
    extension: string;
    width: number;
    height: number;
    ms: number;
    /** Bytes the Content Credential added, or 0 when the export is unsigned. */
    manifestBytes: number;
}

/**
 * What the engine needs in order to sign.
 *
 * The clock and the randomness come from here rather than from Rust because
 * `wasm32-unknown-unknown` has neither. That is a constraint, but it is also
 * the right split: the host owns them, and passing them in keeps signing
 * reproducible.
 */
export interface SignSpec {
    /** `dc:title` for the output. */
    title: string;
    /** RFC 3339 timestamp for every action's `when`. */
    now: string;
    /** `xmpMM:InstanceID` of the output. */
    instanceId: string;
    /** `urn:c2pa:<uuid>` label for the new manifest. */
    manifestId: string;
    /** The opened file, recorded as a parentOf ingredient. */
    sourceName: string;
    sourceMime: string;
    sourceInstanceId: string;
    /** Embed a thumbnail of the result in the manifest. */
    thumbnail: boolean;
}

/* -------------------------------------------------------------------------
   Worker message protocol
   ------------------------------------------------------------------------- */

export type WorkerRequest =
    | { id: number; kind: 'init' }
    | { id: number; kind: 'open'; bytes: ArrayBuffer; name: string; type: string }
    | {
          id: number;
          kind: 'preview';
          /** The real edit, used to report the true export dimensions. */
          pipeline: Pipeline;
          /** What to actually draw - differs from `pipeline` in crop mode. */
          display: Pipeline;
          maxWidth: number;
          maxHeight: number;
      }
    | {
          id: number;
          kind: 'export';
          pipeline: Pipeline;
          encode: EncodeSpec;
          /** Null exports without Content Credentials. */
          sign: SignSpec | null;
      };

export type WorkerResponse =
    | { id: number; ok: true; kind: 'init'; capabilities: Capabilities }
    | { id: number; ok: true; kind: 'open'; source: SourceInfo }
    | { id: number; ok: true; kind: 'preview'; result: PreviewResult }
    | { id: number; ok: true; kind: 'export'; result: ExportPayload }
    | { id: number; ok: false; error: string };
