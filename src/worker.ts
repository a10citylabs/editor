/**
 * The image engine's host thread.
 *
 * Everything expensive - decoding, resampling, warping, encoding - happens
 * here so that dragging a slider never janks the page. The main thread only
 * ever sees finished RGBA buffers and encoded blobs, handed over as transfers
 * rather than copies.
 */

import init, { Editor, capabilities } from './wasm/imagecore.js';
import type { Capabilities, SourceInfo, WorkerRequest, WorkerResponse } from './types';

let ready: Promise<void> | null = null;
let editor: Editor | null = null;

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
async function open(bytes: ArrayBuffer, name: string, type: string): Promise<SourceInfo> {
    const view = new Uint8Array(bytes);
    const hint = name || type;

    try {
        editor?.free();
        editor = Editor.open(view, hint);
        return {
            width: editor.sourceWidth,
            height: editor.sourceHeight,
            format: editor.sourceFormat,
            hasAlpha: editor.hasAlpha,
            viaBrowser: false,
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
        };
    }
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
                const source = await open(request.bytes, request.name, request.type);
                reply({ id: request.id, ok: true, kind: 'open', source });
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
                const encoded = active.renderExport(
                    JSON.stringify(request.pipeline),
                    JSON.stringify(request.encode),
                );
                const bytes = encoded.takeBytes();
                const result = {
                    bytes: bytes.buffer as ArrayBuffer,
                    mime: encoded.mime,
                    extension: encoded.extension,
                    width: encoded.width,
                    height: encoded.height,
                    ms: performance.now() - started,
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
