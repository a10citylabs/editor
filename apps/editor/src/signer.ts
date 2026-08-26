/**
 * The Edge subsystem's client for the claim-signer.
 *
 * # Why there is a network call in a no-upload image editor
 *
 * Because a browser cannot keep a secret, and the C2PA Conformance Program
 * requires that the claim signing key be kept. Objective O.2 of the Generator
 * Product Security Requirements asks for a key that is encrypted at rest,
 * encrypted in memory except while signing, access-controlled by least
 * privilege, and rotatable. A key compiled into a WebAssembly module and served
 * to every visitor satisfies none of those, so a browser-only claim generator
 * cannot reach even Assurance Level 1.
 *
 * What crosses the network is a `Sig_structure`: the claim, the certificate
 * chain, and a context string — a few hundred bytes. The image is not in it.
 * The editor's promise is intact; only the *signature* moved.
 *
 * ```text
 *   this tab                                sign.example.com
 *   ────────────                            ─────────────────────────
 *   GET  /v1/identity            ─────▶     the public certificate chain
 *   build the claim
 *   POST /v1/sign                ─────▶     authenticate, sign, time-stamp
 *        { toBeSigned }          ◀─────     { signature, timestampToken }
 *   assemble and embed
 * ```
 *
 * # Configuration, and what happens without it
 *
 * The editor fetches `claim-signer.json` beside itself at start-up. When it is
 * absent — which it is on the static GitHub Pages build, where there is no
 * application server to mint a session credential — signing is simply
 * unavailable, and the interface says so rather than offering a button that
 * fails. Editing and exporting work exactly as before; the export just carries
 * no credential.
 *
 * ```json
 *   {
 *     "url": "https://sign.example.com",
 *     "credentialEndpoint": "/api/edge-credential"
 *   }
 * ```
 *
 * `credentialEndpoint` returns a short-lived `{ keyId, secret, expiresAt }` for
 * this session. An inline `credential` is accepted too, for a development
 * deployment; the difference is spelt out in
 * `conformance/generator-product-security-architecture.md`.
 */

import type { EdgeCredential, SignerConfig, SigningIdentity, SignedClaim } from './types';

/** Refresh a session credential this long before it expires. */
const CREDENTIAL_MARGIN_MS = 30_000;

/**
 * Read `claim-signer.json` from beside the app.
 *
 * Null means this deployment has no claim-signer, which is a supported
 * configuration rather than a failure: the static build on GitHub Pages has no
 * application server to mint a session credential, so it edits and exports
 * without writing Content Credentials, and says so.
 */
export async function loadSignerConfig(
    url = 'claim-signer.json',
): Promise<SignerConfig | null> {
    try {
        const response = await fetch(url, { cache: 'no-store' });
        if (!response.ok) return null;
        const config = (await response.json()) as SignerConfig;
        return config?.url ? config : null;
    } catch {
        return null;
    }
}

export class SignerUnavailable extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SignerUnavailable';
    }
}

export class ClaimSigner {
    private readonly config: SignerConfig;
    private identity: SigningIdentity | null = null;
    private credential: EdgeCredential | null = null;
    private credentialExpiry = 0;

    private constructor(config: SignerConfig) {
        this.config = config;
    }

    /**
     * Connect to a configured claim-signer and fetch its signing identity.
     *
     * Throws when the service cannot be reached. That is worth distinguishing
     * from "no signer is configured", which [`loadSignerConfig`] reports by
     * returning null, because the two call for different words in front of a
     * user: one is a deployment without credentials, the other is a credential
     * service that is down.
     */
    static async fromConfig(config: SignerConfig): Promise<ClaimSigner> {
        const signer = new ClaimSigner(config);
        await signer.loadIdentity();
        return signer;
    }

    /** The certificate chain and algorithm, once fetched. */
    get signingIdentity(): SigningIdentity | null {
        return this.identity;
    }

    /**
     * Fetch `GET /v1/identity`.
     *
     * Unauthenticated on purpose: everything it returns is public, and needing
     * a credential to learn which certificate the service holds would make the
     * page harder to debug for no gain.
     */
    async loadIdentity(): Promise<SigningIdentity> {
        const response = await fetch(this.endpoint('/v1/identity'), { cache: 'no-store' });
        if (!response.ok) {
            throw new SignerUnavailable(
                `the claim-signer answered ${response.status} when asked for its identity`,
            );
        }
        this.identity = (await response.json()) as SigningIdentity;
        return this.identity;
    }

    /**
     * Sign a `Sig_structure`, returning the signature and any time-stamp.
     *
     * A missing time-stamp is not a failure. The authority may be unreachable,
     * and refusing to save someone's photograph over it would be the wrong
     * trade; the credential is written without one and the interface reports
     * that it will stop validating when the certificate expires.
     */
    async sign(toBeSigned: Uint8Array): Promise<SignedClaim> {
        const body = JSON.stringify({ toBeSigned: toBase64(toBeSigned) });
        const path = '/v1/sign';
        const credential = await this.edgeCredential();

        const response = await fetch(this.endpoint(path), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: await authorization(credential, 'POST', path, body),
            },
            body,
        });

        if (!response.ok) {
            const detail = await response
                .json()
                .then((body: { error?: string }) => body.error)
                .catch(() => undefined);
            throw new SignerUnavailable(
                detail ?? `the claim-signer answered ${response.status}`,
            );
        }

        const result = (await response.json()) as {
            signature: string;
            timestampToken?: string;
            keyId: string;
            timestampError?: string;
        };

        // A rotation between fetching the identity and signing would produce a
        // signature that does not match the certificate already committed to in
        // the manifest. Catching it here turns a silently invalid file into a
        // retry.
        if (this.identity && result.keyId !== this.identity.keyId) {
            this.identity = null;
            throw new SignerUnavailable(
                'the signing key changed while this export was being prepared; try again',
            );
        }

        return {
            signature: fromBase64(result.signature),
            timestampToken: result.timestampToken ? fromBase64(result.timestampToken) : null,
            timestampError: result.timestampError ?? null,
        };
    }

    private endpoint(path: string): string {
        return `${this.config.url.replace(/\/$/, '')}${path}`;
    }

    /** The short-lived credential this session authenticates with. */
    private async edgeCredential(): Promise<EdgeCredential> {
        if (this.credential && Date.now() < this.credentialExpiry - CREDENTIAL_MARGIN_MS) {
            return this.credential;
        }

        if (this.config.credential) {
            this.credential = this.config.credential;
            // An inline credential does not expire on its own; treat it as
            // valid for the session and re-read it if the page reloads.
            this.credentialExpiry = Number.POSITIVE_INFINITY;
            return this.credential;
        }

        if (!this.config.credentialEndpoint) {
            throw new SignerUnavailable(
                'this deployment has no way to authenticate to the claim-signer',
            );
        }

        const response = await fetch(this.config.credentialEndpoint, {
            method: 'POST',
            credentials: 'same-origin',
        });
        if (!response.ok) {
            throw new SignerUnavailable(
                `could not obtain a signing session (${response.status})`,
            );
        }
        const credential = (await response.json()) as EdgeCredential;
        this.credential = credential;
        this.credentialExpiry = credential.expiresAt
            ? Date.parse(credential.expiresAt)
            : Date.now() + 300_000;
        return credential;
    }
}

/**
 * Build the `Authorization` header the claim-signer expects.
 *
 * `HMAC-SHA256(secret, method ‖ path ‖ timestamp ‖ nonce ‖ hex(SHA-256(body)))`,
 * matching `services/claim-signer/src/auth.rs`. MACing the body rather than
 * issuing a bearer token is what stops a captured header being pointed at a
 * different claim.
 */
async function authorization(
    credential: EdgeCredential,
    method: string,
    path: string,
    body: string,
): Promise<string> {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = randomHex(16);
    const encoder = new TextEncoder();

    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(body));
    const canonical = [method, path, String(timestamp), nonce, toHex(new Uint8Array(digest))].join(
        '\n',
    );

    const key = await crypto.subtle.importKey(
        'raw',
        fromBase64(credential.secret) as BufferSource,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const mac = await crypto.subtle.sign('HMAC', key, encoder.encode(canonical));

    return `C2PA-HMAC-SHA256 key=${credential.keyId}, ts=${timestamp}, nonce=${nonce}, mac=${toBase64(
        new Uint8Array(mac),
    )}`;
}

function randomHex(bytes: number): string {
    return toHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function toBase64(bytes: Uint8Array): string {
    // Chunked so a large Sig_structure cannot blow the argument limit of
    // `String.fromCharCode`.
    let binary = '';
    const chunk = 0x8000;
    for (let at = 0; at < bytes.length; at += chunk) {
        binary += String.fromCharCode(...bytes.subarray(at, at + chunk));
    }
    return btoa(binary);
}

export function fromBase64(text: string): Uint8Array {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let at = 0; at < binary.length; at += 1) bytes[at] = binary.charCodeAt(at);
    return bytes;
}
