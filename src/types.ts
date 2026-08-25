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
}

export interface SourceInfo {
    width: number;
    height: number;
    format: string;
    hasAlpha: boolean;
    /** Set when the browser decoded the file instead of the Rust engine. */
    viaBrowser: boolean;
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
    | { id: number; kind: 'export'; pipeline: Pipeline; encode: EncodeSpec };

export type WorkerResponse =
    | { id: number; ok: true; kind: 'init'; capabilities: Capabilities }
    | { id: number; ok: true; kind: 'open'; source: SourceInfo }
    | { id: number; ok: true; kind: 'preview'; result: PreviewResult }
    | { id: number; ok: true; kind: 'export'; result: ExportPayload }
    | { id: number; ok: false; error: string };
