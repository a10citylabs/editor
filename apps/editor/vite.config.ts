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

    server: {
        // Reach a locally running claim-signer without falling foul of the
        // same-origin policy. The service serves no CORS headers — deliberately,
        // since the deployment it is written for puts the Edge and the Backend
        // behind one origin — so a page on :5173 cannot call :8443 directly.
        //
        // Point `claim-signer.json` at `"url": "/signer"` and requests arrive
        // here instead. The rewrite is the part that matters and is not
        // optional: the Edge computes its request MAC over the literal path
        // `/v1/sign`, and `auth.rs` recomputes it over the path the service
        // receives, so anything that forwards `/signer/v1/sign` unstripped
        // fails authentication. A production reverse proxy has to strip its
        // prefix for the same reason — see services/claim-signer/TESTING.md.
        proxy: {
            '/signer': {
                target: process.env.CLAIM_SIGNER_ORIGIN ?? 'http://127.0.0.1:8443',
                changeOrigin: true,
                // Trust a self-signed certificate, so the TLS path can be
                // exercised locally rather than only the plaintext one.
                secure: false,
                rewrite: (path) => path.replace(/^\/signer/, ''),
            },
        },
    },
});
