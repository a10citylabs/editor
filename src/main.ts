/**
 * A10city Image Editor - application wiring.
 *
 * The UI holds one declarative `Pipeline`. Every control mutates it and asks
 * for a redraw; the worker replays that pipeline from the pristine decoded
 * source each time. Nothing here touches pixels.
 */

import { Engine } from './engine';
import { CropOverlay } from './crop';
import type {
    Capabilities,
    CropRect,
    EncodeSpec,
    OutputFormatInfo,
    Pipeline,
    PreviewResult,
    ResampleFilter,
    SourceInfo,
} from './types';

/* -------------------------------------------------------------------------
   Element lookup
   ------------------------------------------------------------------------- */

function el<T extends HTMLElement = HTMLElement>(id: string): T {
    const node = document.getElementById(id);
    if (!node) throw new Error(`The page is missing #${id}.`);
    return node as T;
}

const ui = {
    dropzone: el('dropzone'),
    fileInput: el<HTMLInputElement>('file-input'),
    inputFormats: el('input-formats'),

    canvasShell: el('canvas-shell'),
    canvasViewport: el('canvas-viewport'),
    canvasFrame: el('canvas-frame'),
    canvas: el<HTMLCanvasElement>('preview-canvas'),
    busy: el('stage-busy'),

    cropOverlay: el('crop-overlay'),
    cropBox: el('crop-box'),

    fileName: el('file-name'),
    sourceFormat: el('source-format'),
    compareBtn: el<HTMLButtonElement>('compare-btn'),
    resetBtn: el<HTMLButtonElement>('reset-btn'),
    replaceBtn: el<HTMLButtonElement>('replace-btn'),

    statusSource: el('status-source'),
    statusOutput: el('status-output'),
    statusTiming: el('status-timing'),

    error: el('stage-error'),
    errorMessage: el('stage-error-message'),

    panelCrop: el<HTMLDetailsElement>('panel-crop'),

    rotCcw: el<HTMLButtonElement>('rot-ccw'),
    rotCw: el<HTMLButtonElement>('rot-cw'),
    flipH: el<HTMLButtonElement>('flip-h'),
    flipV: el<HTMLButtonElement>('flip-v'),
    angle: el<HTMLInputElement>('angle-input'),
    angleReadout: el('angle-readout'),
    matteRow: el('matte-row'),
    matteReadout: el('matte-readout'),
    matteInput: el<HTMLInputElement>('matte-input'),

    cropBadge: el('crop-badge'),
    aspectRow: el('aspect-row'),
    cropX: el<HTMLInputElement>('crop-x'),
    cropY: el<HTMLInputElement>('crop-y'),
    cropW: el<HTMLInputElement>('crop-w'),
    cropH: el<HTMLInputElement>('crop-h'),
    cropClear: el<HTMLButtonElement>('crop-clear'),
    cropCenter: el<HTMLButtonElement>('crop-center'),

    resizeBadge: el('resize-badge'),
    resizeW: el<HTMLInputElement>('resize-w'),
    resizeH: el<HTMLInputElement>('resize-h'),
    lockAspect: el<HTMLInputElement>('lock-aspect'),
    resizeFilter: el<HTMLSelectElement>('resize-filter'),
    resizeClear: el<HTMLButtonElement>('resize-clear'),

    adjustBadge: el('adjust-badge'),
    adjBrightness: el<HTMLInputElement>('adj-brightness'),
    adjContrast: el<HTMLInputElement>('adj-contrast'),
    adjSaturation: el<HTMLInputElement>('adj-saturation'),
    adjSharpen: el<HTMLInputElement>('adj-sharpen'),
    adjBlur: el<HTMLInputElement>('adj-blur'),
    adjGrayscale: el<HTMLInputElement>('adj-grayscale'),
    adjInvert: el<HTMLInputElement>('adj-invert'),

    formatRow: el('format-row'),
    qualityRow: el('quality-row'),
    quality: el<HTMLInputElement>('quality-input'),
    qualityReadout: el('quality-readout'),
    pngRow: el('png-row'),
    pngCompression: el<HTMLSelectElement>('png-compression'),
    flattenRow: el('flatten-row'),
    flattenReadout: el('flatten-readout'),
    flattenInput: el<HTMLInputElement>('flatten-input'),
    exportName: el<HTMLInputElement>('export-name'),
    exportBtn: el<HTMLButtonElement>('export-btn'),
    exportLabel: el('export-label'),
    exportNote: el('export-note'),

    engineLine: el('engine-line'),
};

/* -------------------------------------------------------------------------
   State
   ------------------------------------------------------------------------- */

function emptyPipeline(): Pipeline {
    return {
        crop: null,
        flipH: false,
        flipV: false,
        quarterTurns: 0,
        angle: 0,
        background: [0, 0, 0, 0],
        resize: null,
        adjust: {
            brightness: 0,
            contrast: 0,
            saturation: 0,
            grayscale: false,
            invert: false,
            blur: 0,
            sharpen: 0,
        },
    };
}

const engine = new Engine();

let capabilities: Capabilities | null = null;
let source: SourceInfo | null = null;
let pipeline = emptyPipeline();
let encode: EncodeSpec = {
    format: 'png',
    quality: 85,
    pngCompression: 'default',
    background: [255, 255, 255],
};

let sourceName = 'image';
let cropAspect: number | null = null;
let comparing = false;
let exporting = false;
/** Output dimensions as last reported by the engine. */
let outputDims = { width: 0, height: 0 };

const crop = new CropOverlay({
    overlay: ui.cropOverlay,
    box: ui.cropBox,
    shades: {
        top: ui.cropOverlay.querySelector<HTMLElement>('.crop-shade-top')!,
        bottom: ui.cropOverlay.querySelector<HTMLElement>('.crop-shade-bottom')!,
        left: ui.cropOverlay.querySelector<HTMLElement>('.crop-shade-left')!,
        right: ui.cropOverlay.querySelector<HTMLElement>('.crop-shade-right')!,
    },
    onChange: (rect) => {
        pipeline.crop = rect;
        syncCropFields();
        refresh();
    },
});

/* -------------------------------------------------------------------------
   Rendering
   ------------------------------------------------------------------------- */

/**
 * While the Crop panel is open, the preview shows the untrimmed frame with the
 * selection drawn over it - you cannot adjust a crop you have already been
 * cropped out of. Collapsing the panel shows the composed result.
 */
function cropMode(): boolean {
    return ui.panelCrop.open && Boolean(source);
}

function displayPipeline(): Pipeline {
    if (comparing) return emptyPipeline();
    if (cropMode()) return { ...pipeline, crop: null, resize: null };
    return pipeline;
}

/**
 * The preview box, in both the units that matter.
 *
 * `css` is the space on screen the image has to fit into; `device` is how many
 * real pixels that space is worth, which is what the engine renders. On a
 * HiDPI screen the two differ by the pixel ratio, and conflating them is what
 * makes a canvas come out stretched: the backing store is sized in device
 * pixels but laid out in CSS ones.
 */
function previewBox(): { cssWidth: number; cssHeight: number; width: number; height: number } {
    // `clientWidth`/`clientHeight` round to whole pixels while the padding
    // does not, which can overstate the box by most of a pixel - enough for
    // the canvas to poke out from under the crop overlay. The rect is exact.
    const rect = ui.canvasViewport.getBoundingClientRect();
    const style = getComputedStyle(ui.canvasViewport);
    const padX =
        parseFloat(style.paddingLeft) +
        parseFloat(style.paddingRight) +
        parseFloat(style.borderLeftWidth) +
        parseFloat(style.borderRightWidth);
    const padY =
        parseFloat(style.paddingTop) +
        parseFloat(style.paddingBottom) +
        parseFloat(style.borderTopWidth) +
        parseFloat(style.borderBottomWidth);

    const cssWidth = Math.max(0, rect.width - padX);
    const cssHeight = Math.max(0, rect.height - padY);

    // The render resolution is a separate question: never ask the engine for
    // a postage stamp, and never for more pixels than a screen can show.
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    return {
        cssWidth,
        cssHeight,
        width: Math.min(Math.max(160, Math.round(cssWidth * dpr)), 2400),
        height: Math.min(Math.max(160, Math.round(cssHeight * dpr)), 2400),
    };
}

/**
 * Scale `w` x `h` down until it fits inside the box, keeping the ratio and
 * never enlarging. The mirror of `ops::fit_within` in the engine, so the
 * layout maths and the render maths agree on what "fits" means.
 */
function fitWithin(
    w: number,
    h: number,
    maxW: number,
    maxH: number,
): { width: number; height: number } {
    if (w <= 0 || h <= 0) return { width: 0, height: 0 };
    const scale = Math.min(maxW / w, maxH / h, 1);
    return { width: w * scale, height: h * scale };
}

/**
 * Give the canvas an explicit display size instead of leaving it to `max-width`
 * and the flex algorithm, which size the two axes independently and so throw
 * the aspect ratio away. Fitting the frame we actually received into the box
 * we actually have is also self-correcting: a window resize between asking for
 * a frame and drawing it costs a little sharpness, never a stretched image.
 */
function layoutCanvas(): void {
    if (!ui.canvas.width || !ui.canvas.height) return;
    const box = previewBox();
    // A collapsed box means the stage is hidden; leave the last good size in
    // place rather than flattening the canvas to nothing.
    if (box.cssWidth <= 0 || box.cssHeight <= 0) return;

    const size = fitWithin(ui.canvas.width, ui.canvas.height, box.cssWidth, box.cssHeight);
    ui.canvas.style.width = `${size.width}px`;
    ui.canvas.style.height = `${size.height}px`;
}

/**
 * Flashing a spinner for a 15ms render is worse than showing nothing, so the
 * busy state only appears once a render has visibly outstayed its welcome.
 */
const BUSY_DELAY_MS = 180;
let busyTimer: number | undefined;

function setBusy(on: boolean): void {
    window.clearTimeout(busyTimer);
    if (!on) {
        ui.busy.hidden = true;
        return;
    }
    busyTimer = window.setTimeout(() => {
        ui.busy.hidden = false;
    }, BUSY_DELAY_MS);
}

function refresh(): void {
    if (!source) return;
    syncBadges();
    setBusy(true);

    const box = previewBox();
    engine.requestPreview(
        { pipeline, display: displayPipeline(), maxWidth: box.width, maxHeight: box.height },
        onFrame,
        (message) => {
            setBusy(false);
            showError(message);
        },
    );
}

function onFrame(frame: PreviewResult): void {
    clearError();
    // Keep the indicator up only while a newer frame is still on its way.
    setBusy(engine.previewQueued);

    const ctx = ui.canvas.getContext('2d');
    if (!ctx) {
        setBusy(false);
        showError('This browser could not provide a 2D canvas to draw on.');
        return;
    }

    ui.canvas.width = frame.width;
    ui.canvas.height = frame.height;
    ctx.putImageData(
        new ImageData(new Uint8ClampedArray(frame.pixels), frame.width, frame.height),
        0,
        0,
    );
    layoutCanvas();

    // The overlay tracks the frame it is drawn on, which in crop mode is the
    // untrimmed image and therefore exactly crop space.
    crop.setSpace(frame.cropSpaceWidth, frame.cropSpaceHeight);
    outputDims = { width: frame.outputWidth, height: frame.outputHeight };

    ui.statusOutput.textContent = `${frame.outputWidth} x ${frame.outputHeight}`;
    ui.statusTiming.textContent = `${frame.ms.toFixed(0)} ms`;
    ui.cropOverlay.hidden = !cropMode() || comparing;

    syncCropFields();
    syncResizeFields();
    syncExportControls();
}

/* -------------------------------------------------------------------------
   Loading
   ------------------------------------------------------------------------- */

async function load(file: File): Promise<void> {
    clearError();
    setBusy(true);

    try {
        const info = await engine.open(file);
        source = info;
        sourceName = file.name.replace(/\.[^.]+$/, '') || 'image';

        pipeline = emptyPipeline();
        cropAspect = null;
        comparing = false;
        resetControlValues();

        ui.dropzone.hidden = true;
        ui.canvasShell.hidden = false;
        ui.fileName.textContent = file.name;
        ui.sourceFormat.textContent = info.viaBrowser
            ? `${info.format} (browser)`
            : info.format;
        ui.statusSource.textContent = `${info.width} x ${info.height}`;
        ui.exportBtn.disabled = false;

        encode = {
            ...encode,
            format: defaultOutputFormat(info),
        };
        buildFormatChips();
        ui.exportName.value = `${sourceName}-edited`;

        refresh();
    } catch (error) {
        showError(error instanceof Error ? error.message : String(error));
    }
}

/**
 * Default to writing back the format that came in, so "open, rotate, save"
 * does not silently change someone's file type. Formats we can read but not
 * write fall back to PNG.
 */
function defaultOutputFormat(info: SourceInfo): string {
    const writable = capabilities?.outputs.some((f) => f.id === info.format);
    return writable ? info.format : 'png';
}

/* -------------------------------------------------------------------------
   Control synchronisation
   ------------------------------------------------------------------------- */

function resetControlValues(): void {
    ui.angle.value = '0';
    ui.angleReadout.textContent = '0.0°';
    ui.flipH.setAttribute('aria-pressed', 'false');
    ui.flipV.setAttribute('aria-pressed', 'false');
    ui.matteRow.hidden = true;

    crop.setRect(null);
    crop.setAspect(null);
    setActiveChip(ui.aspectRow, 'free', 'aspect');

    ui.adjBrightness.value = '0';
    ui.adjContrast.value = '0';
    ui.adjSaturation.value = '0';
    ui.adjSharpen.value = '0';
    ui.adjBlur.value = '0';
    ui.adjGrayscale.checked = false;
    ui.adjInvert.checked = false;
    syncAdjustReadouts();

    ui.exportNote.textContent = '';
    ui.exportNote.classList.remove('ok');
}

function syncBadges(): void {
    ui.cropBadge.hidden = !pipeline.crop;
    ui.resizeBadge.hidden = !pipeline.resize;
    const a = pipeline.adjust;
    ui.adjustBadge.hidden = !(
        a.brightness || a.contrast || a.saturation || a.blur || a.sharpen || a.grayscale || a.invert
    );
}

function syncCropFields(): void {
    const space = crop.getSpace();
    const rect = pipeline.crop;

    for (const [input, max] of [
        [ui.cropX, space.width],
        [ui.cropY, space.height],
        [ui.cropW, space.width],
        [ui.cropH, space.height],
    ] as const) {
        input.max = String(max);
    }

    if (document.activeElement && isCropField(document.activeElement)) return;

    ui.cropX.value = String(rect?.x ?? 0);
    ui.cropY.value = String(rect?.y ?? 0);
    ui.cropW.value = String(rect?.width ?? space.width);
    ui.cropH.value = String(rect?.height ?? space.height);
}

function isCropField(node: Element): boolean {
    return node === ui.cropX || node === ui.cropY || node === ui.cropW || node === ui.cropH;
}

function syncResizeFields(): void {
    if (document.activeElement === ui.resizeW || document.activeElement === ui.resizeH) return;
    ui.resizeW.value = String(outputDims.width || '');
    ui.resizeH.value = String(outputDims.height || '');
}

function syncAdjustReadouts(): void {
    const pairs: [HTMLInputElement, string, number][] = [
        [ui.adjBrightness, 'adj-brightness-out', 2],
        [ui.adjContrast, 'adj-contrast-out', 2],
        [ui.adjSaturation, 'adj-saturation-out', 2],
        [ui.adjSharpen, 'adj-sharpen-out', 2],
        [ui.adjBlur, 'adj-blur-out', 1],
    ];
    for (const [input, outId, digits] of pairs) {
        const value = Number(input.value);
        el(outId).textContent = value === 0 ? '0' : value.toFixed(digits);
    }
}

function currentFormat(): OutputFormatInfo | undefined {
    return capabilities?.outputs.find((f) => f.id === encode.format);
}

function syncExportControls(): void {
    const format = currentFormat();
    if (!format) return;

    ui.qualityRow.hidden = !format.lossy;
    ui.pngRow.hidden = format.id !== 'png';

    // Only offer a matte when something could actually be transparent.
    const couldBeTransparent = Boolean(source?.hasAlpha) || pipeline.angle !== 0;
    ui.flattenRow.hidden = format.alpha || !couldBeTransparent;

    const name = ui.exportName.value.replace(/\.[^.]+$/, '') || sourceName;
    ui.exportLabel.textContent = exporting
        ? 'Encoding…'
        : `Download ${format.label}`;
    ui.exportName.dataset.stem = name;
}

/* -------------------------------------------------------------------------
   Format chips
   ------------------------------------------------------------------------- */

function buildFormatChips(): void {
    if (!capabilities) return;
    ui.formatRow.replaceChildren();

    const ordered = [...capabilities.outputs].sort(
        (a, b) => Number(b.common) - Number(a.common),
    );

    for (const format of ordered) {
        const chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'chip';
        chip.dataset.format = format.id;
        chip.textContent = format.label;
        chip.setAttribute('aria-pressed', String(format.id === encode.format));
        if (format.id === encode.format) chip.classList.add('is-active');

        chip.addEventListener('click', () => {
            encode = { ...encode, format: format.id };
            setActiveChip(ui.formatRow, format.id, 'format');
            syncExportControls();
            ui.exportNote.textContent = '';
            ui.exportNote.classList.remove('ok');
        });

        ui.formatRow.append(chip);
    }
    syncExportControls();
}

function setActiveChip(container: HTMLElement, value: string, key: string): void {
    for (const chip of container.querySelectorAll<HTMLElement>('.chip')) {
        const active = chip.dataset[key] === value;
        chip.classList.toggle('is-active', active);
        chip.setAttribute('aria-pressed', String(active));
    }
}

/* -------------------------------------------------------------------------
   Geometry helpers
   ------------------------------------------------------------------------- */

/**
 * Move the crop selection with the picture when it is turned or mirrored, so
 * the same subject stays selected.
 *
 * This is exact while the straighten dial is at zero. With a free angle in
 * play the crop frame is not simply a transpose of itself, so the remapped
 * rectangle is an approximation that the engine then clamps into bounds.
 */
function remapCrop(transform: 'cw' | 'ccw' | 'mirror-x' | 'mirror-y'): void {
    const rect = pipeline.crop;
    if (!rect) return;
    const { width: W, height: H } = crop.getSpace();

    const next: CropRect =
        transform === 'cw'
            ? { x: H - (rect.y + rect.height), y: rect.x, width: rect.height, height: rect.width }
            : transform === 'ccw'
              ? { x: rect.y, y: W - (rect.x + rect.width), width: rect.height, height: rect.width }
              : transform === 'mirror-x'
                ? { ...rect, x: W - (rect.x + rect.width) }
                : { ...rect, y: H - (rect.y + rect.height) };

    pipeline.crop = next;
    crop.setRect(next);
}

/** A flip applied before an odd number of quarter turns reads as the other axis. */
function mirrorAxisInCropSpace(flip: 'h' | 'v'): 'mirror-x' | 'mirror-y' {
    const swapped = pipeline.quarterTurns % 2 === 1;
    const horizontal = flip === 'h' ? !swapped : swapped;
    return horizontal ? 'mirror-x' : 'mirror-y';
}

function quarterTurn(direction: 1 | -1): void {
    remapCrop(direction === 1 ? 'cw' : 'ccw');
    pipeline.quarterTurns = (pipeline.quarterTurns + direction + 4) % 4;
    // A pending resize target described the old orientation; swap it too.
    if (pipeline.resize) {
        pipeline.resize = {
            ...pipeline.resize,
            width: pipeline.resize.height,
            height: pipeline.resize.width,
        };
    }
    refresh();
}

function hexToRgb(hex: string): [number, number, number] {
    const value = hex.replace('#', '');
    const full =
        value.length === 3
            ? value
                  .split('')
                  .map((c) => c + c)
                  .join('')
            : value;
    return [
        parseInt(full.slice(0, 2), 16) || 0,
        parseInt(full.slice(2, 4), 16) || 0,
        parseInt(full.slice(4, 6), 16) || 0,
    ];
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/* -------------------------------------------------------------------------
   Errors
   ------------------------------------------------------------------------- */

function showError(message: string): void {
    setBusy(false);
    ui.error.hidden = false;
    ui.errorMessage.textContent = message;
}

function clearError(): void {
    ui.error.hidden = true;
    ui.errorMessage.textContent = '';
}

/* -------------------------------------------------------------------------
   Wiring
   ------------------------------------------------------------------------- */

function wireFileInput(): void {
    const pick = () => ui.fileInput.click();

    ui.dropzone.addEventListener('click', pick);
    ui.replaceBtn.addEventListener('click', pick);
    ui.dropzone.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            pick();
        }
    });

    ui.fileInput.addEventListener('change', () => {
        const file = ui.fileInput.files?.[0];
        if (file) void load(file);
        ui.fileInput.value = '';
    });

    for (const event of ['dragenter', 'dragover'] as const) {
        ui.dropzone.addEventListener(event, (e) => {
            e.preventDefault();
            ui.dropzone.classList.add('dragover');
        });
    }
    for (const event of ['dragleave', 'dragend'] as const) {
        ui.dropzone.addEventListener(event, () => ui.dropzone.classList.remove('dragover'));
    }
    ui.dropzone.addEventListener('drop', (event) => {
        event.preventDefault();
        ui.dropzone.classList.remove('dragover');
        const file = event.dataTransfer?.files?.[0];
        if (file) void load(file);
    });

    // Dropping anywhere on the page is the behaviour people expect once an
    // image is already open.
    document.addEventListener('dragover', (event) => event.preventDefault());
    document.addEventListener('drop', (event) => {
        if (ui.dropzone.contains(event.target as Node)) return;
        event.preventDefault();
        const file = event.dataTransfer?.files?.[0];
        if (file) void load(file);
    });

    // Paste from the clipboard.
    document.addEventListener('paste', (event) => {
        const file = Array.from(event.clipboardData?.files ?? [])[0];
        if (file) void load(file);
    });
}

function wireTransform(): void {
    ui.rotCw.addEventListener('click', () => quarterTurn(1));
    ui.rotCcw.addEventListener('click', () => quarterTurn(-1));

    ui.flipH.addEventListener('click', () => {
        remapCrop(mirrorAxisInCropSpace('h'));
        pipeline.flipH = !pipeline.flipH;
        ui.flipH.setAttribute('aria-pressed', String(pipeline.flipH));
        refresh();
    });

    ui.flipV.addEventListener('click', () => {
        remapCrop(mirrorAxisInCropSpace('v'));
        pipeline.flipV = !pipeline.flipV;
        ui.flipV.setAttribute('aria-pressed', String(pipeline.flipV));
        refresh();
    });

    ui.angle.addEventListener('input', () => {
        pipeline.angle = Number(ui.angle.value);
        ui.angleReadout.textContent = `${pipeline.angle.toFixed(1)}°`;
        ui.matteRow.hidden = pipeline.angle === 0;
        // A free rotation resizes the frame, so a pending resize target no
        // longer describes anything the user chose.
        pipeline.resize = null;
        syncExportControls();
        refresh();
    });

    // Double-click the straighten slider to snap back to level.
    ui.angle.addEventListener('dblclick', () => {
        ui.angle.value = '0';
        ui.angle.dispatchEvent(new Event('input'));
    });

    for (const swatch of ui.matteRow.querySelectorAll<HTMLElement>('.swatch')) {
        swatch.addEventListener('click', () => {
            const value = swatch.dataset.matte ?? 'transparent';
            pipeline.background =
                value === 'transparent' ? [0, 0, 0, 0] : [...hexToRgb(value), 255];
            ui.matteReadout.textContent = value === 'transparent' ? 'Transparent' : value;
            for (const other of ui.matteRow.querySelectorAll<HTMLElement>('.swatch')) {
                const active = other === swatch;
                other.classList.toggle('is-active', active);
                other.setAttribute('aria-pressed', String(active));
            }
            refresh();
        });
    }

    ui.matteInput.addEventListener('input', () => {
        pipeline.background = [...hexToRgb(ui.matteInput.value), 255];
        ui.matteReadout.textContent = ui.matteInput.value;
        for (const other of ui.matteRow.querySelectorAll<HTMLElement>('.swatch')) {
            other.classList.remove('is-active');
            other.setAttribute('aria-pressed', 'false');
        }
        refresh();
    });
}

function wireCrop(): void {
    ui.panelCrop.addEventListener('toggle', () => {
        ui.cropOverlay.hidden = !cropMode();
        refresh();
    });

    for (const chip of ui.aspectRow.querySelectorAll<HTMLElement>('.chip')) {
        chip.addEventListener('click', () => {
            const value = chip.dataset.aspect ?? 'free';
            cropAspect = value === 'free' ? null : Number(value);
            setActiveChip(ui.aspectRow, value, 'aspect');
            crop.setAspect(cropAspect);
            if (cropAspect && !pipeline.crop) {
                const rect = crop.centred();
                pipeline.crop = rect;
                crop.setRect(rect);
                refresh();
            }
        });
    }

    const commitFields = () => {
        const space = crop.getSpace();
        const rect: CropRect = {
            x: Number(ui.cropX.value) || 0,
            y: Number(ui.cropY.value) || 0,
            width: Number(ui.cropW.value) || space.width,
            height: Number(ui.cropH.value) || space.height,
        };
        crop.setRect(rect);
        pipeline.crop = crop.getRect();
        refresh();
    };

    for (const input of [ui.cropX, ui.cropY, ui.cropW, ui.cropH]) {
        input.addEventListener('change', commitFields);
    }

    ui.cropClear.addEventListener('click', () => {
        pipeline.crop = null;
        crop.setRect(null);
        syncCropFields();
        refresh();
    });

    ui.cropCenter.addEventListener('click', () => {
        const rect = crop.centred();
        pipeline.crop = rect;
        crop.setRect(rect);
        syncCropFields();
        refresh();
    });
}

function wireResize(): void {
    const commit = (changed: 'w' | 'h') => {
        const base = { width: outputDims.width, height: outputDims.height };
        const ratio = base.height > 0 ? base.width / base.height : 1;

        let width = Math.max(1, Math.round(Number(ui.resizeW.value) || base.width));
        let height = Math.max(1, Math.round(Number(ui.resizeH.value) || base.height));

        if (ui.lockAspect.checked) {
            if (changed === 'w') height = Math.max(1, Math.round(width / ratio));
            else width = Math.max(1, Math.round(height * ratio));
        }

        ui.resizeW.value = String(width);
        ui.resizeH.value = String(height);
        pipeline.resize = {
            width,
            height,
            filter: ui.resizeFilter.value as ResampleFilter,
        };
        refresh();
    };

    ui.resizeW.addEventListener('change', () => commit('w'));
    ui.resizeH.addEventListener('change', () => commit('h'));

    ui.resizeFilter.addEventListener('change', () => {
        if (pipeline.resize) {
            pipeline.resize = {
                ...pipeline.resize,
                filter: ui.resizeFilter.value as ResampleFilter,
            };
            refresh();
        }
    });

    for (const chip of document.querySelectorAll<HTMLElement>('[data-scale]')) {
        chip.addEventListener('click', () => {
            const scale = Number(chip.dataset.scale);
            if (!scale || !outputDims.width) return;
            pipeline.resize = {
                width: Math.max(1, Math.round(outputDims.width * scale)),
                height: Math.max(1, Math.round(outputDims.height * scale)),
                filter: ui.resizeFilter.value as ResampleFilter,
            };
            refresh();
        });
    }

    ui.resizeClear.addEventListener('click', () => {
        pipeline.resize = null;
        refresh();
    });
}

function wireAdjust(): void {
    const inputs: [HTMLInputElement, keyof Pipeline['adjust']][] = [
        [ui.adjBrightness, 'brightness'],
        [ui.adjContrast, 'contrast'],
        [ui.adjSaturation, 'saturation'],
        [ui.adjSharpen, 'sharpen'],
        [ui.adjBlur, 'blur'],
    ];

    for (const [input, key] of inputs) {
        input.addEventListener('input', () => {
            (pipeline.adjust[key] as number) = Number(input.value);
            syncAdjustReadouts();
            refresh();
        });
        input.addEventListener('dblclick', () => {
            input.value = '0';
            input.dispatchEvent(new Event('input'));
        });
    }

    ui.adjGrayscale.addEventListener('change', () => {
        pipeline.adjust.grayscale = ui.adjGrayscale.checked;
        refresh();
    });
    ui.adjInvert.addEventListener('change', () => {
        pipeline.adjust.invert = ui.adjInvert.checked;
        refresh();
    });
}

function wireExport(): void {
    ui.quality.addEventListener('input', () => {
        encode = { ...encode, quality: Number(ui.quality.value) };
        ui.qualityReadout.textContent = ui.quality.value;
    });

    ui.pngCompression.addEventListener('change', () => {
        encode = {
            ...encode,
            pngCompression: ui.pngCompression.value as EncodeSpec['pngCompression'],
        };
    });

    for (const swatch of ui.flattenRow.querySelectorAll<HTMLElement>('.swatch')) {
        swatch.addEventListener('click', () => {
            const value = swatch.dataset.flatten ?? '#ffffff';
            encode = { ...encode, background: hexToRgb(value) };
            ui.flattenReadout.textContent = value;
            for (const other of ui.flattenRow.querySelectorAll<HTMLElement>('.swatch')) {
                const active = other === swatch;
                other.classList.toggle('is-active', active);
                other.setAttribute('aria-pressed', String(active));
            }
        });
    }

    ui.flattenInput.addEventListener('input', () => {
        encode = { ...encode, background: hexToRgb(ui.flattenInput.value) };
        ui.flattenReadout.textContent = ui.flattenInput.value;
        for (const other of ui.flattenRow.querySelectorAll<HTMLElement>('.swatch')) {
            other.classList.remove('is-active');
            other.setAttribute('aria-pressed', 'false');
        }
    });

    ui.exportBtn.addEventListener('click', () => void runExport());
}

async function runExport(): Promise<void> {
    if (!source || exporting) return;

    exporting = true;
    ui.exportBtn.disabled = true;
    ui.exportBtn.classList.add('is-working');
    ui.exportNote.classList.remove('ok');
    ui.exportNote.textContent = 'Encoding…';
    syncExportControls();

    try {
        const payload = await engine.export(pipeline, encode);
        const stem = (ui.exportName.value.replace(/\.[^.]+$/, '') || sourceName).trim();
        const filename = `${stem || 'image'}.${payload.extension}`;

        const blob = new Blob([payload.bytes], { type: payload.mime });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
        document.body.append(anchor);
        anchor.click();
        anchor.remove();
        // Revoking immediately can race the download in some browsers.
        setTimeout(() => URL.revokeObjectURL(url), 60_000);

        ui.exportNote.textContent = `${filename} · ${payload.width} x ${payload.height} · ${formatBytes(
            blob.size,
        )} · ${payload.ms.toFixed(0)} ms`;
        ui.exportNote.classList.add('ok');
        clearError();
    } catch (error) {
        ui.exportNote.textContent = '';
        showError(error instanceof Error ? error.message : String(error));
    } finally {
        exporting = false;
        ui.exportBtn.disabled = false;
        ui.exportBtn.classList.remove('is-working');
        syncExportControls();
    }
}

function wireStage(): void {
    ui.resetBtn.addEventListener('click', () => {
        if (!source) return;
        pipeline = emptyPipeline();
        cropAspect = null;
        resetControlValues();
        refresh();
    });

    // Hold the compare button to see the original.
    const startCompare = () => {
        if (!source || comparing) return;
        comparing = true;
        ui.compareBtn.setAttribute('aria-pressed', 'true');
        ui.canvasFrame.classList.add('comparing');
        ui.cropOverlay.hidden = true;
        refresh();
    };
    const endCompare = () => {
        if (!comparing) return;
        comparing = false;
        ui.compareBtn.setAttribute('aria-pressed', 'false');
        ui.canvasFrame.classList.remove('comparing');
        refresh();
    };

    ui.compareBtn.addEventListener('pointerdown', startCompare);
    ui.compareBtn.addEventListener('pointerup', endCompare);
    ui.compareBtn.addEventListener('pointerleave', endCompare);
    ui.compareBtn.addEventListener('pointercancel', endCompare);
    ui.compareBtn.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            startCompare();
        }
    });
    ui.compareBtn.addEventListener('keyup', endCompare);
    ui.compareBtn.addEventListener('blur', endCompare);

    // Re-fit what is already on screen straight away so the image never lags
    // the box it sits in, then re-render once the drag settles to recover the
    // resolution the new box is worth.
    let resizeTimer: number | undefined;
    window.addEventListener('resize', () => {
        layoutCanvas();
        window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(() => refresh(), 150);
    });
}

function wireShortcuts(): void {
    document.addEventListener('keydown', (event) => {
        const target = event.target as HTMLElement | null;
        const typing =
            target instanceof HTMLInputElement ||
            target instanceof HTMLTextAreaElement ||
            target instanceof HTMLSelectElement;
        if (typing || event.metaKey || event.ctrlKey || event.altKey || !source) return;

        switch (event.key.toLowerCase()) {
            case 'r':
                quarterTurn(event.shiftKey ? -1 : 1);
                event.preventDefault();
                break;
            case 'h':
                ui.flipH.click();
                event.preventDefault();
                break;
            case 'v':
                ui.flipV.click();
                event.preventDefault();
                break;
            case 'c':
                ui.panelCrop.open = !ui.panelCrop.open;
                event.preventDefault();
                break;
            default:
                break;
        }
    });
}

/* -------------------------------------------------------------------------
   Boot
   ------------------------------------------------------------------------- */

async function boot(): Promise<void> {
    wireFileInput();
    wireTransform();
    wireCrop();
    wireResize();
    wireAdjust();
    wireExport();
    wireStage();
    wireShortcuts();

    try {
        capabilities = await engine.init();

        ui.inputFormats.replaceChildren(
            ...[...capabilities.inputs, 'avif*', 'svg*'].map((name) => {
                const tag = document.createElement('span');
                tag.className = 'format-tag';
                tag.textContent = name;
                return tag;
            }),
        );

        buildFormatChips();

        ui.engineLine.innerHTML =
            `imagecore v${capabilities.version} · Rust → WebAssembly` +
            (capabilities.simd ? ' · <span class="accent">SIMD</span>' : '') +
            '<br>* decoded by your browser';
    } catch (error) {
        showError(
            error instanceof Error
                ? `The image engine did not start: ${error.message}`
                : 'The image engine did not start.',
        );
    }
}

void boot();
