/**
 * The image engine's host thread.
 *
 * Everything expensive - decoding, resampling, warping, encoding - happens
 * here so that dragging a slider never janks the page. The main thread only
 * ever sees finished RGBA buffers and encoded blobs, handed over as transfers
 * rather than copies.
 */

import init, {
    Editor,
    capabilities,
    describeSigningIdentity,
} from './wasm/imagecore.js';
import { ClaimSigner, SignerUnavailable } from './signer';
import type {
    Capabilities,
    CredentialReport,
    SignerConfig,
    SignerDescription,
    SourceInfo,
    ValidationRequest,
    WorkerRequest,
    WorkerResponse,
} from './types';

let ready: Promise<void> | null = null;
let editor: Editor | null = null;
/** Object URL for the open file's manifest thumbnail, revoked on replacement. */
let credentialThumbnailUrl: string | null = null;
/**
 * The Backend subsystem, once configured.
 *
 * Held here rather than on the main thread because the whole signing round trip
 * happens on this side: the engine produces the bytes to be signed, the network
 * call goes out, and the finished file comes back. Passing the intermediate
 * `Sig_structure` across the worker boundary and back would double the copies
 * for no benefit.
 */
let signer: ClaimSigner | null = null;

function ensureReady(): Promise<void> {
    if (!ready) {
        ready = init().then(() => undefined);
    }
    return ready;
}

/**
 * Decode with the Rust engine, falling back to the browser's own decoders.
 *
 * AVIF, HEIC and SVG are the cases that matter: shipping decoders for them
 * would add megabytes of WebAssembly for formats the browser already handles,
 * so we let it hand us raw RGBA instead.
 */
async function open(
    bytes: ArrayBuffer,
    name: string,
    type: string,
    validation: ValidationRequest,
): Promise<SourceInfo> {
    const view = new Uint8Array(bytes);
    const hint = name || type;

    try {
        editor?.free();
        editor = Editor.open(view, hint, JSON.stringify(validation));
        return {
            width: editor.sourceWidth,
            height: editor.sourceHeight,
            format: editor.sourceFormat,
            hasAlpha: editor.hasAlpha,
            viaBrowser: false,
            ...readCredentials(editor),
        };
    } catch (engineError) {
        const pixels = await decodeInBrowser(bytes, type, engineError);
        editor?.free();
        editor = Editor.openRaw(pixels.data, pixels.width, pixels.height, pixels.label);
        return {
            width: pixels.width,
            height: pixels.height,
            format: pixels.label,
            hasAlpha: true,
            viaBrowser: true,
            // A browser-decoded image reaches us as raw pixels, so whatever
            // container it arrived in - and any credential inside it - is gone.
            credentials: null,
            credentialThumbnail: null,
        };
    }
}

/**
 * Pull the validated Content Credentials, if any, off a freshly opened file.
 *
 * The manifest thumbnail becomes an object URL here rather than in the UI
 * because the bytes are already on this side of the worker boundary; sending
 * them to the main thread only to wrap them there would copy them twice.
 */
function readCredentials(open: Editor): Pick<SourceInfo, 'credentials' | 'credentialThumbnail'> {
    const raw = open.credentials;
    if (!raw) return { credentials: null, credentialThumbnail: null };

    let credentials: CredentialReport;
    try {
        credentials = JSON.parse(raw) as CredentialReport;
    } catch {
        return { credentials: null, credentialThumbnail: null };
    }

    // The previous file's thumbnail URL is released here rather than on open,
    // so the UI can keep showing it until a replacement exists.
    if (credentialThumbnailUrl) URL.revokeObjectURL(credentialThumbnailUrl);
    // wasm-bindgen returns an owned copy for a `Vec<u8>`, so the buffer is ours
    // to hand to a Blob rather than a view into the engine's memory.
    const thumbnail = open.credentialThumbnail();
    credentialThumbnailUrl = thumbnail
        ? URL.createObjectURL(
              new Blob([thumbnail.buffer as ArrayBuffer], { type: 'image/jpeg' }),
          )
        : null;

    return { credentials, credentialThumbnail: credentialThumbnailUrl };
}

async function decodeInBrowser(
    bytes: ArrayBuffer,
    type: string,
    engineError: unknown,
): Promise<{ data: Uint8Array; width: number; height: number; label: string }> {
    if (typeof createImageBitmap !== 'function' || typeof OffscreenCanvas !== 'function') {
        throw engineError;
    }

    let bitmap: ImageBitmap;
    try {
        bitmap = await createImageBitmap(new Blob([bytes], type ? { type } : undefined));
    } catch {
        // The browser could not read it either, so the engine's message is the
        // more useful one to surface.
        throw engineError;
    }

    try {
        const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        if (!ctx) throw engineError;
        ctx.drawImage(bitmap, 0, 0);
        const image = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
        return {
            data: new Uint8Array(image.data.buffer.slice(0)),
            width: bitmap.width,
            height: bitmap.height,
            label: labelFromMime(type),
        };
    } finally {
        bitmap.close();
    }
}

function labelFromMime(type: string): string {
    const subtype = type.split('/')[1] ?? '';
    return subtype ? subtype.replace(/^x-/, '').split('+')[0] : 'browser';
}

/**
 * Point the worker at a claim-signer, and report who it says it is.
 *
 * A configuration that is absent, or a service that cannot be reached, is not
 * an error here: the editor still works and still exports, just without a
 * credential. The interface needs to know which of the two happened, so both
 * come back rather than collapsing into a null.
 */
async function connectSigner(
    config: SignerConfig | null,
): Promise<{ identity: SignerDescription | null; problem: string | null }> {
    signer = null;
    if (!config) {
        return { identity: null, problem: null };
    }

    try {
        const client = await ClaimSigner.fromConfig(config);
        const identity = client.signingIdentity;
        if (!identity) {
            return { identity: null, problem: 'the claim-signer did not answer' };
        }
        signer = client;
        // Parse the chain in Rust rather than trusting the service's summary of
        // itself: the certificate is the authority on the Assurance Level and
        // the Conforming Products List record, and the Edge is about to commit
        // to it in a manifest.
        return {
            identity: JSON.parse(
                describeSigningIdentity(JSON.stringify(identity)),
            ) as SignerDescription,
            problem: null,
        };
    } catch (error) {
        return { identity: null, problem: messageOf(error) };
    }
}

/**
 * Build the manifest, send the claim for signing, and finish the file.
 *
 * The three steps are separate calls into the engine because a network round
 * trip sits between the second and the third. `abandonSignedExport` matters:
 * without it a failed signature would leave the engine holding a half-built
 * manifest that the next export would trip over.
 */
async function exportSigned(
    active: Editor,
    pipeline: unknown,
    encode: unknown,
    sign: unknown,
): Promise<{ encoded: ReturnType<Editor['renderExport']>; timeStampError: string | null }> {
    if (!signer?.signingIdentity) {
        throw new Error(
            'Content Credentials need a claim-signer, and none is configured for this deployment.',
        );
    }

    const pending = active.prepareSignedExport(
        JSON.stringify(pipeline),
        JSON.stringify(encode),
        JSON.stringify(sign),
        JSON.stringify(signer.signingIdentity),
    );

    let toBeSigned: Uint8Array;
    try {
        toBeSigned = pending.takeToBeSigned();
    } finally {
        pending.free();
    }

    try {
        const signed = await signer.sign(toBeSigned);
        return {
            encoded: active.completeSignedExport(
                signed.signature,
                signed.timestampToken ?? undefined,
            ),
            timeStampError: signed.timestampError,
        };
    } catch (error) {
        active.abandonSignedExport();
        if (error instanceof SignerUnavailable) {
            throw new Error(`Could not sign: ${error.message}`);
        }
        throw error;
    }
}

function requireEditor(): Editor {
    if (!editor) throw new Error('No image is open yet.');
    return editor;
}

function messageOf(error: unknown): string {
    if (error instanceof Error) return error.message;
    return typeof error === 'string' ? error : 'Something went wrong in the image engine.';
}

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
    const request = event.data;
    const reply = (response: WorkerResponse, transfer: Transferable[] = []) =>
        (self as unknown as Worker).postMessage(response, transfer);

    try {
        await ensureReady();

        switch (request.kind) {
            case 'init': {
                const caps = JSON.parse(capabilities()) as Capabilities;
                reply({ id: request.id, ok: true, kind: 'init', capabilities: caps });
                break;
            }

            case 'open': {
                const source = await open(
                    request.bytes,
                    request.name,
                    request.type,
                    request.validation,
                );
                reply({ id: request.id, ok: true, kind: 'open', source });
                break;
            }

            case 'signer': {
                const { identity, problem } = await connectSigner(request.config);
                reply({ id: request.id, ok: true, kind: 'signer', identity, problem });
                break;
            }

            case 'preview': {
                const active = requireEditor();
                const started = performance.now();

                // The true pipeline decides the reported export size; the
                // display pipeline decides what actually gets drawn.
                const dims = JSON.parse(active.outputDims(JSON.stringify(request.pipeline))) as {
                    width: number;
                    height: number;
                    cropSpaceWidth: number;
                    cropSpaceHeight: number;
                };

                const frame = active.renderPreview(
                    JSON.stringify(request.display),
                    request.maxWidth,
                    request.maxHeight,
                );
                const pixels = frame.takePixels();
                const result = {
                    pixels: pixels.buffer as ArrayBuffer,
                    width: frame.width,
                    height: frame.height,
                    outputWidth: dims.width,
                    outputHeight: dims.height,
                    cropSpaceWidth: dims.cropSpaceWidth,
                    cropSpaceHeight: dims.cropSpaceHeight,
                    ms: performance.now() - started,
                };
                frame.free();

                reply({ id: request.id, ok: true, kind: 'preview', result }, [result.pixels]);
                break;
            }

            case 'export': {
                const active = requireEditor();
                const started = performance.now();
                const { encoded, timeStampError } = request.sign
                    ? await exportSigned(active, request.pipeline, request.encode, request.sign)
                    : {
                          encoded: active.renderExport(
                              JSON.stringify(request.pipeline),
                              JSON.stringify(request.encode),
                          ),
                          timeStampError: null,
                      };

                const bytes = encoded.takeBytes();
                const result = {
                    bytes: bytes.buffer as ArrayBuffer,
                    mime: encoded.mime,
                    extension: encoded.extension,
                    width: encoded.width,
                    height: encoded.height,
                    ms: performance.now() - started,
                    manifestBytes: encoded.manifestBytes,
                    timeStamped: encoded.timeStamped,
                    timeStampError,
                };
                encoded.free();

                reply({ id: request.id, ok: true, kind: 'export', result }, [result.bytes]);
                break;
            }
        }
    } catch (error) {
        reply({ id: request.id, ok: false, error: messageOf(error) });
    }
};
