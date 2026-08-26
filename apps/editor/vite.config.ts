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
        // `npm run build` is invoked from the repository root, so the output
        // goes where the deploy workflow expects it rather than beside the app.
        outDir: '../../dist',
        emptyOutDir: true,
        target: 'esnext',
        // A 2MB engine is expected; warning about it every build is noise.
        chunkSizeWarningLimit: 4096,
    },

    worker: {
        format: 'es',
    },
});
