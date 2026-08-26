/**
 * Main-thread client for the WebAssembly image worker.
 *
 * Requests are correlated by id so several can be in flight at once, and
 * previews get their own scheduler: while one frame is rendering, newer
 * requests replace each other instead of queueing up. Dragging a slider then
 * costs one render per frame the engine can actually deliver, rather than one
 * per pixel of slider travel.
 */

import type {
    Capabilities,
    EncodeSpec,
    ExportPayload,
    Pipeline,
    PreviewResult,
    SignerConfig,
    SignerDescription,
    SignSpec,
    SourceInfo,
    ValidationRequest,
    WorkerRequest,
    WorkerResponse,
} from './types';

interface PreviewRequest {
    pipeline: Pipeline;
    display: Pipeline;
    maxWidth: number;
    maxHeight: number;
}

/**
 * `Omit` collapses a union to its shared keys, which would erase every
 * request variant's payload. Distributing over the union keeps them.
 */
type Unaddressed<T> = T extends unknown ? Omit<T, 'id'> : never;

type Pending = {
    resolve: (value: WorkerResponse) => void;
    reject: (reason: Error) => void;
};

export class Engine {
    private readonly worker: Worker;
    private readonly pending = new Map<number, Pending>();
    private nextId = 1;

    private queuedPreview: PreviewRequest | null = null;
    private previewRunning = false;

    constructor() {
        this.worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });

        this.worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
            const response = event.data;
            const pending = this.pending.get(response.id);
            if (!pending) return;
            this.pending.delete(response.id);
            pending.resolve(response);
        };

        this.worker.onerror = (event) => {
            const error = new Error(
                event.message || 'The image engine failed to start. Try reloading the page.',
            );
            for (const pending of this.pending.values()) pending.reject(error);
            this.pending.clear();
        };
    }

    private send(request: Unaddressed<WorkerRequest>, transfer: Transferable[] = []) {
        const id = this.nextId++;
        const message = { ...request, id } as WorkerRequest;
        return new Promise<WorkerResponse>((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            this.worker.postMessage(message, transfer);
        });
    }

    private static unwrap(response: WorkerResponse): Extract<WorkerResponse, { ok: true }> {
        if (!response.ok) throw new Error(response.error);
        return response;
    }

    async init(): Promise<Capabilities> {
        const response = Engine.unwrap(await this.send({ kind: 'init' }));
        if (response.kind !== 'init') throw new Error('Unexpected reply from the image engine.');
        return response.capabilities;
    }

    async open(file: File, validation: ValidationRequest): Promise<SourceInfo> {
        const bytes = await file.arrayBuffer();
        const response = Engine.unwrap(
            await this.send(
                { kind: 'open', bytes, name: file.name, type: file.type, validation },
                [bytes],
            ),
        );
        if (response.kind !== 'open') throw new Error('Unexpected reply from the image engine.');
        return response.source;
    }

    /**
     * Point the engine at a claim-signer, or at nothing.
     *
     * Returns what the certificate says about the signer, or the reason it
     * could not be reached. Both are useful to show; conflating them would
     * leave a user unable to tell a deployment without credentials from a
     * credential service that is down.
     */
    async connectSigner(
        config: SignerConfig | null,
    ): Promise<{ identity: SignerDescription | null; problem: string | null }> {
        const response = Engine.unwrap(await this.send({ kind: 'signer', config }));
        if (response.kind !== 'signer') throw new Error('Unexpected reply from the image engine.');
        return { identity: response.identity, problem: response.problem };
    }

    /**
     * Render and encode. Passing `sign` also writes Content Credentials, which
     * the engine rejects for any format but JPEG rather than silently dropping.
     *
     * A signed export makes a network round trip to the claim-signer in the
     * middle, so it takes longer than an unsigned one and can fail for reasons
     * that have nothing to do with the image.
     */
    async export(
        pipeline: Pipeline,
        encode: EncodeSpec,
        sign: SignSpec | null = null,
    ): Promise<ExportPayload> {
        const response = Engine.unwrap(await this.send({ kind: 'export', pipeline, encode, sign }));
        if (response.kind !== 'export') throw new Error('Unexpected reply from the image engine.');
        return response.result;
    }

    /**
     * Ask for a preview. If one is already rendering, this replaces whatever
     * was waiting behind it, so only the newest state is ever drawn.
     */
    requestPreview(
        request: PreviewRequest,
        onFrame: (frame: PreviewResult) => void,
        onError: (message: string) => void,
    ): void {
        this.queuedPreview = request;
        if (this.previewRunning) return;

        this.previewRunning = true;
        void (async () => {
            try {
                while (this.queuedPreview) {
                    const next = this.queuedPreview;
                    this.queuedPreview = null;
                    const response = await this.send({ kind: 'preview', ...next });
                    if (!response.ok) {
                        onError(response.error);
                        continue;
                    }
                    if (response.kind === 'preview') onFrame(response.result);
                }
            } catch (error) {
                onError(error instanceof Error ? error.message : String(error));
            } finally {
                this.previewRunning = false;
            }
        })();
    }

    /**
     * True when another preview is already waiting to be drawn. Note this is
     * deliberately *not* "a render is in flight": by the time a frame reaches
     * the UI its own render has finished, and only a queued successor means
     * what is on screen is about to be replaced.
     */
    get previewQueued(): boolean {
        return this.queuedPreview !== null;
    }
}
