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

/**
 * What the *engine* can do with Content Credentials.
 *
 * Note the absence of a signer. The Edge subsystem holds no key and no
 * certificate; it learns both from the claim-signer at run time. That is a
 * requirement of the C2PA Conformance Program rather than a design preference
 * - see `crates/imagecore/src/c2pa/identity.rs`.
 */
export interface CredentialSupport {
    available: boolean;
    /** Output formats a manifest can be written to. JPEG only - see the
     *  module docs in `crates/imagecore/src/c2pa/mod.rs` for why. */
    formats?: string[];
    /** The C2PA specification version this build writes to. */
    specVersion?: string;
    /** Always true now: signing needs the Backend subsystem. */
    remoteSigning?: boolean;
    timeStamping?: boolean;
}

/** Where the claim-signer is and how to authenticate to it. */
export interface SignerConfig {
    /** Base URL of the claim-signer, e.g. `https://sign.example.com`. */
    url: string;
    /** Endpoint that mints a short-lived Edge credential for this session. */
    credentialEndpoint?: string;
    /** A fixed credential, for a development deployment. */
    credential?: EdgeCredential;
}

/** The Edge subsystem's authentication key. Scoped to limiting access to the
 *  Backend and to nothing else, per objective O.2. */
export interface EdgeCredential {
    keyId: string;
    /** Base64 HMAC secret. */
    secret: string;
    /** ISO-8601. Absent means "for this session". */
    expiresAt?: string;
}

/** `GET /v1/identity` from the claim-signer: the public half of the credential. */
export interface SigningIdentity {
    /** PEM chain, leaf first, trust anchor omitted. */
    chainPem: string;
    /** COSE algorithm name, e.g. `ES256`. */
    algorithm: string;
    keyId: string;
    /** Bytes to reserve for a time-stamp token; 0 when none is configured. */
    timestampBudget: number;
    assuranceLevel: number | null;
    cplRecordId: string | null;
    notAfter: string;
}

/** What `describeSigningIdentity` reports, for the interface to show. */
export interface SignerDescription {
    commonName: string;
    organisation: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
    algorithm: string;
    /** From the `c2pa-al` extension: 1 or 2, or null when the certificate was
     *  not issued under the C2PA Certificate Policy. */
    assuranceLevel: number | null;
    /** The Conforming Products List record this instance signs under. */
    cplRecordId: string | null;
    /** Whether the leaf asserts `c2pa-kp-claimSigning`. */
    claimSigningEku: boolean;
    timeStamped: boolean;
    keyId: string;
}

/** What the claim-signer returned for one claim. */
export interface SignedClaim {
    signature: Uint8Array;
    /** DER `TimeStampToken`, or null when none could be obtained. */
    timestampToken: Uint8Array | null;
    /** Why there is no time-stamp, when there is none. */
    timestampError: string | null;
}

/**
 * What a validator needs that WebAssembly cannot find for itself.
 *
 * These are the four inputs the C2PA Conformance Program's test harness takes,
 * minus the asset: a validation time and two trust lists. An absent trust list
 * means "check the integrity and report the identity as unchecked", never
 * "trust everything".
 */
export interface ValidationRequest {
    /** RFC 3339 instant to judge certificate validity at. */
    now: string;
    /** PEM bundle of C2PA trust anchors. */
    trustListPem?: string;
    /** PEM bundle of TSA trust anchors. */
    tsaTrustListPem?: string;
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
    /** IPTC digital source type. Mandatory on most predefined actions under
     *  the Conformance Program's additional requirements. */
    digitalSourceType: string;
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
    serialNumber: string;
    notBefore: string;
    notAfter: string;
    /** Whether a trusted RFC 3161 time-stamp was found. */
    timeStamped: boolean;
    /** The attested time, when there was one. */
    timeStamp: string;
    timeStampAuthority: string;
    /** Whether the chain reached an anchor on the supplied C2PA Trust List. */
    trusted: boolean;
    trustAnchor: string;
    /** From the `c2pa-al` extension. */
    assuranceLevel: number | null;
    /** From the `c2pa-cpl-record` extension. */
    cplRecordId: string;
}

export interface CredentialManifest {
    /** The `urn:c2pa:` label. */
    label: string;
    title: string;
    instanceId: string;
    generator: string;
    /** The `specVersion` the generator declared. */
    specVersion: string;
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
    /** True when every check that was applied passed. With no trust list
     *  configured, that excludes the signer's identity, which is reported as
     *  unchecked rather than as a pass. */
    valid: boolean;
    /** The instant validity was judged at, RFC 3339. */
    validationTime: string;
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
    /** Whether the credential carries a time-stamp. */
    timeStamped: boolean;
    /** Why it does not, when it does not. */
    timeStampError: string | null;
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
    | {
          id: number;
          kind: 'open';
          bytes: ArrayBuffer;
          name: string;
          type: string;
          /** What the validator needs and WebAssembly cannot find for itself. */
          validation: ValidationRequest;
      }
    | {
          id: number;
          kind: 'signer';
          /** Null disconnects, leaving the editor able to export unsigned. */
          config: SignerConfig | null;
      }
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
    | {
          id: number;
          ok: true;
          kind: 'signer';
          /** Null when no claim-signer is configured or it could not be
           *  reached; `problem` says which. */
          identity: SignerDescription | null;
          problem: string | null;
      }
    | { id: number; ok: true; kind: 'open'; source: SourceInfo }
    | { id: number; ok: true; kind: 'preview'; result: PreviewResult }
    | { id: number; ok: true; kind: 'export'; result: ExportPayload }
    | { id: number; ok: false; error: string };
