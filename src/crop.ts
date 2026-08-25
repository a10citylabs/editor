/**
 * The interactive crop selection.
 *
 * The rectangle is stored in crop-space pixels - the frame the engine measures
 * crops against, i.e. the source after flips and rotation - and painted as
 * percentages of the canvas. Storing it that way means a window resize, a zoom
 * or a different preview resolution never disturbs the selection, and the
 * numbers in the sidebar are the real pixel coordinates rather than something
 * screen-relative.
 */

import type { CropRect } from './types';

type DragMode = 'new' | 'move' | 'nw' | 'n' | 'ne' | 'e' | 'se' | 's' | 'sw' | 'w';

interface DragState {
    mode: DragMode;
    pointerId: number;
    /** Selection as it was when the drag began. */
    origin: CropRect;
    /** Pointer position in crop-space pixels when the drag began. */
    startX: number;
    startY: number;
}

/** Never let a selection collapse to something unclickable. */
const MIN_SIZE = 8;

export interface CropOverlayOptions {
    overlay: HTMLElement;
    box: HTMLElement;
    shades: {
        top: HTMLElement;
        bottom: HTMLElement;
        left: HTMLElement;
        right: HTMLElement;
    };
    onChange: (rect: CropRect | null, committed: boolean) => void;
}

export class CropOverlay {
    private readonly options: CropOverlayOptions;
    private spaceWidth = 1;
    private spaceHeight = 1;
    private rect: CropRect | null = null;
    private aspect: number | null = null;
    private drag: DragState | null = null;

    constructor(options: CropOverlayOptions) {
        this.options = options;

        options.overlay.addEventListener('pointerdown', this.onPointerDown);
        options.overlay.addEventListener('pointermove', this.onPointerMove);
        options.overlay.addEventListener('pointerup', this.onPointerUp);
        options.overlay.addEventListener('pointercancel', this.onPointerUp);
        options.box.addEventListener('keydown', this.onKeyDown);
    }

    /** Tell the overlay how large the frame it sits on is, in real pixels. */
    setSpace(width: number, height: number): void {
        const changed = width !== this.spaceWidth || height !== this.spaceHeight;
        this.spaceWidth = Math.max(1, Math.round(width));
        this.spaceHeight = Math.max(1, Math.round(height));
        if (changed && this.rect) {
            this.rect = this.clamp(this.rect);
        }
        this.paint();
    }

    getSpace(): { width: number; height: number } {
        return { width: this.spaceWidth, height: this.spaceHeight };
    }

    setRect(rect: CropRect | null): void {
        this.rect = rect ? this.clamp(rect) : null;
        this.paint();
    }

    getRect(): CropRect | null {
        return this.rect ? { ...this.rect } : null;
    }

    /** Width / height, or null for a free selection. */
    setAspect(aspect: number | null): void {
        this.aspect = aspect;
        if (aspect && this.rect) {
            this.rect = this.clamp(this.fitAspect(this.rect, aspect, 'nw'));
            this.paint();
            this.options.onChange(this.getRect(), true);
        }
    }

    /** A centred selection covering most of the frame, for the "Centre" button. */
    centred(coverage = 0.8): CropRect {
        let width = Math.round(this.spaceWidth * coverage);
        let height = Math.round(this.spaceHeight * coverage);
        if (this.aspect) {
            if (width / height > this.aspect) width = Math.round(height * this.aspect);
            else height = Math.round(width / this.aspect);
        }
        return this.clamp({
            x: Math.round((this.spaceWidth - width) / 2),
            y: Math.round((this.spaceHeight - height) / 2),
            width,
            height,
        });
    }

    /* --------------------------------------------------------------------
       Painting
       -------------------------------------------------------------------- */

    private paint(): void {
        const { box, shades, overlay } = this.options;
        if (!this.rect) {
            box.hidden = true;
            for (const shade of Object.values(shades)) shade.hidden = true;
            return;
        }

        box.hidden = false;
        const left = (this.rect.x / this.spaceWidth) * 100;
        const top = (this.rect.y / this.spaceHeight) * 100;
        const width = (this.rect.width / this.spaceWidth) * 100;
        const height = (this.rect.height / this.spaceHeight) * 100;

        box.style.left = `${left}%`;
        box.style.top = `${top}%`;
        box.style.width = `${width}%`;
        box.style.height = `${height}%`;

        for (const shade of Object.values(shades)) shade.hidden = false;
        Object.assign(shades.top.style, { left: '0', top: '0', right: '0', height: `${top}%` });
        Object.assign(shades.bottom.style, {
            left: '0',
            top: `${top + height}%`,
            right: '0',
            bottom: '0',
        });
        Object.assign(shades.left.style, {
            left: '0',
            top: `${top}%`,
            width: `${left}%`,
            height: `${height}%`,
        });
        Object.assign(shades.right.style, {
            left: `${left + width}%`,
            top: `${top}%`,
            right: '0',
            height: `${height}%`,
        });

        overlay.setAttribute(
            'aria-label',
            `Crop selection: ${this.rect.width} by ${this.rect.height} pixels at ${this.rect.x}, ${this.rect.y}`,
        );
    }

    /* --------------------------------------------------------------------
       Geometry
       -------------------------------------------------------------------- */

    private toSpace(event: PointerEvent): { x: number; y: number } {
        const bounds = this.options.overlay.getBoundingClientRect();
        const fx = bounds.width > 0 ? (event.clientX - bounds.left) / bounds.width : 0;
        const fy = bounds.height > 0 ? (event.clientY - bounds.top) / bounds.height : 0;
        return {
            x: Math.round(Math.min(Math.max(fx, 0), 1) * this.spaceWidth),
            y: Math.round(Math.min(Math.max(fy, 0), 1) * this.spaceHeight),
        };
    }

    private clamp(rect: CropRect): CropRect {
        const maxW = this.spaceWidth;
        const maxH = this.spaceHeight;
        const width = Math.min(Math.max(Math.round(rect.width), Math.min(MIN_SIZE, maxW)), maxW);
        const height = Math.min(Math.max(Math.round(rect.height), Math.min(MIN_SIZE, maxH)), maxH);
        return {
            width,
            height,
            x: Math.min(Math.max(Math.round(rect.x), 0), maxW - width),
            y: Math.min(Math.max(Math.round(rect.y), 0), maxH - height),
        };
    }

    /**
     * Force a rectangle onto the locked ratio, keeping `anchor`'s corner put.
     * Whichever side is currently too long is the one that gives way, so a
     * drag never suddenly grows in the direction you are not pulling.
     */
    private fitAspect(rect: CropRect, aspect: number, anchor: DragMode): CropRect {
        let { x, y, width, height } = rect;
        const drivenByHeight = anchor === 'n' || anchor === 's';

        if (drivenByHeight) {
            width = height * aspect;
        } else if (anchor === 'e' || anchor === 'w') {
            height = width / aspect;
        } else if (width / height > aspect) {
            width = height * aspect;
        } else {
            height = width / aspect;
        }

        // Re-anchor: the edges named by the handle must not move.
        if (anchor === 'nw' || anchor === 'w' || anchor === 'sw') x = rect.x + rect.width - width;
        if (anchor === 'nw' || anchor === 'n' || anchor === 'ne') y = rect.y + rect.height - height;
        if (anchor === 'n' || anchor === 's') x = rect.x + rect.width / 2 - width / 2;
        if (anchor === 'e' || anchor === 'w') y = rect.y + rect.height / 2 - height / 2;

        return { x: Math.round(x), y: Math.round(y), width: Math.round(width), height: Math.round(height) };
    }

    /* --------------------------------------------------------------------
       Pointer handling
       -------------------------------------------------------------------- */

    private onPointerDown = (event: PointerEvent) => {
        if (event.button !== 0 && event.pointerType === 'mouse') return;
        const target = event.target as HTMLElement;
        const handle = target.closest<HTMLElement>('.crop-handle');
        const onBox = target.closest<HTMLElement>('.crop-box');

        const point = this.toSpace(event);
        let mode: DragMode;
        let origin: CropRect;

        if (handle) {
            mode = (handle.dataset.handle ?? 'se') as DragMode;
            origin = this.rect ?? { x: point.x, y: point.y, width: MIN_SIZE, height: MIN_SIZE };
        } else if (onBox && this.rect) {
            mode = 'move';
            origin = { ...this.rect };
        } else {
            mode = 'new';
            origin = { x: point.x, y: point.y, width: 0, height: 0 };
        }

        this.drag = { mode, pointerId: event.pointerId, origin, startX: point.x, startY: point.y };
        this.options.overlay.setPointerCapture(event.pointerId);
        event.preventDefault();

        if (mode === 'new') {
            // Do not commit a zero-size rect; wait for actual movement.
            this.rect = null;
            this.paint();
        }
    };

    private onPointerMove = (event: PointerEvent) => {
        const drag = this.drag;
        if (!drag || drag.pointerId !== event.pointerId) return;

        const point = this.toSpace(event);
        const next = this.resolveDrag(drag, point);
        if (!next) return;

        this.rect = this.clamp(next);
        this.paint();
        this.options.onChange(this.getRect(), false);
    };

    private onPointerUp = (event: PointerEvent) => {
        const drag = this.drag;
        if (!drag || drag.pointerId !== event.pointerId) return;
        this.drag = null;
        if (this.options.overlay.hasPointerCapture(event.pointerId)) {
            this.options.overlay.releasePointerCapture(event.pointerId);
        }

        // A click with no drag clears the selection rather than leaving a
        // sliver behind.
        if (drag.mode === 'new' && !this.rect) {
            this.options.onChange(null, true);
            return;
        }
        this.options.onChange(this.getRect(), true);
    };

    private resolveDrag(drag: DragState, point: { x: number; y: number }): CropRect | null {
        const { mode, origin, startX, startY } = drag;

        if (mode === 'move') {
            return { ...origin, x: origin.x + (point.x - startX), y: origin.y + (point.y - startY) };
        }

        if (mode === 'new') {
            const width = Math.abs(point.x - startX);
            const height = Math.abs(point.y - startY);
            if (width < 2 && height < 2) return null;
            const raw = {
                x: Math.min(startX, point.x),
                y: Math.min(startY, point.y),
                width,
                height,
            };
            // Anchor on the corner the drag started from.
            const anchor: DragMode =
                point.x >= startX ? (point.y >= startY ? 'se' : 'ne') : point.y >= startY ? 'sw' : 'nw';
            return this.aspect ? this.fitAspect(raw, this.aspect, anchor) : raw;
        }

        // Edge and corner handles: move only the edges the handle names.
        let { x, y, width, height } = origin;
        const right = origin.x + origin.width;
        const bottom = origin.y + origin.height;

        if (mode.includes('w')) {
            x = Math.min(point.x, right - MIN_SIZE);
            width = right - x;
        }
        if (mode.includes('e')) {
            width = Math.max(point.x - origin.x, MIN_SIZE);
        }
        if (mode.includes('n')) {
            y = Math.min(point.y, bottom - MIN_SIZE);
            height = bottom - y;
        }
        if (mode.includes('s')) {
            height = Math.max(point.y - origin.y, MIN_SIZE);
        }

        const raw = { x, y, width, height };
        return this.aspect ? this.fitAspect(raw, this.aspect, oppositeAnchor(mode)) : raw;
    }

    private onKeyDown = (event: KeyboardEvent) => {
        if (!this.rect) return;
        const step = event.shiftKey ? 10 : 1;
        let dx = 0;
        let dy = 0;

        switch (event.key) {
            case 'ArrowLeft': dx = -step; break;
            case 'ArrowRight': dx = step; break;
            case 'ArrowUp': dy = -step; break;
            case 'ArrowDown': dy = step; break;
            case 'Escape':
                this.rect = null;
                this.paint();
                this.options.onChange(null, true);
                event.preventDefault();
                return;
            default:
                return;
        }

        event.preventDefault();
        this.rect = this.clamp({ ...this.rect, x: this.rect.x + dx, y: this.rect.y + dy });
        this.paint();
        this.options.onChange(this.getRect(), true);
    };
}

/**
 * When dragging the east edge, the west edge is what must stay put. Aspect
 * correction anchors on that opposite side.
 */
function oppositeAnchor(mode: DragMode): DragMode {
    const flipped = mode
        .replace('n', 'S')
        .replace('s', 'N')
        .replace('e', 'W')
        .replace('w', 'E')
        .toLowerCase();
    return flipped as DragMode;
}
