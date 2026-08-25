import { defineConfig } from 'vite';

export default defineConfig({
    // GitHub Pages serves this repo under /editor/, matching a10city.com/editor.
    base: process.env.GITHUB_ACTIONS ? '/editor/' : '/',

    // The wasm-pack output is loaded through `new URL(...)`, so Vite should
    // treat it as an asset rather than trying to pre-bundle it.
    optimizeDeps: {
        exclude: ['./src/wasm/imagecore.js'],
    },

    build: {
        target: 'esnext',
        // A 2MB engine is expected; warning about it every build is noise.
        chunkSizeWarningLimit: 4096,
    },

    worker: {
        format: 'es',
    },
});
