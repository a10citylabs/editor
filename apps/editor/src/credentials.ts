/**
 * The Content Credentials panel.
 *
 * Two jobs, and they are separate on purpose:
 *
 *   1. Report what the *opened* file carries, and whether it holds up.
 *   2. Offer to write a credential into the *exported* file.
 *
 * The hard part of both is saying something true. A C2PA manifest supports two
 * quite different claims — "these pixels have not changed since signing" and
 * "this named party signed them" — and they are reported as separate lines
 * because they are separately true. Integrity comes from the hard binding.
 * Identity comes from the signing certificate chaining to a trust anchor, and
 * whether that check even ran depends on whether a trust list was configured.
 *
 * So there are three states, not two, and the wording distinguishes them:
 *
 *   - **trusted** — the chain reached an anchor on the supplied trust list
 *   - **not checked** — no trust list was configured, so nobody looked
 *   - **untrusted** — a list was supplied and the chain did not reach it
 *
 * Collapsing the middle one into either of the others is the failure mode C2PA
 * exists to prevent: someone believing a picture because an interface told them
 * to, or dismissing a good one because it said the wrong thing.
 */

import type {
    CredentialManifest,
    CredentialReport,
    CredentialSupport,
    SignerDescription,
    SourceInfo,
} from './types';

/** Readable names for the predefined action vocabulary (C2PA 2.2, table 8). */
const ACTION_LABELS: Record<string, string> = {
    'c2pa.created': 'Created',
    'c2pa.opened': 'Opened',
    'c2pa.placed': 'Placed into',
    'c2pa.cropped': 'Cropped',
    'c2pa.resized': 'Resized',
    'c2pa.orientation': 'Rotated or flipped',
    'c2pa.adjustedColor': 'Colour adjusted',
    'c2pa.color_adjustments': 'Colour adjusted',
    'c2pa.filtered': 'Filtered',
    'c2pa.enhanced': 'Enhanced',
    'c2pa.edited': 'Edited',
    'c2pa.edited.metadata': 'Metadata edited',
    'c2pa.converted': 'Format converted',
    'c2pa.transcoded': 'Re-encoded',
    'c2pa.repackaged': 'Repackaged',
    'c2pa.drawing': 'Drawn on',
    'c2pa.addedText': 'Text added',
    'c2pa.deleted': 'Content deleted',
    'c2pa.removed': 'Ingredient removed',
    'c2pa.redacted': 'Redacted',
    'c2pa.watermarked': 'Watermarked',
    'c2pa.published': 'Published',
    'c2pa.unknown': 'Unspecified change',
};

function actionLabel(action: string): string {
    if (ACTION_LABELS[action]) return ACTION_LABELS[action];
    // An entity-specific action such as com.example.gaussianBlur. Show the last
    // segment rather than the whole reversed domain, which is just noise.
    const tail = action.split('.').pop() ?? action;
    return tail.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, (c) => c.toUpperCase());
}

/** `2026-08-25T12:00:00Z` reads better as `25 Aug 2026, 12:00`. */
function formatWhen(iso: string): string {
    if (!iso) return '';
    const at = new Date(iso);
    if (Number.isNaN(at.getTime())) return iso;
    return at.toLocaleString(undefined, {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    });
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

interface Elements {
    panel: HTMLDetailsElement;
    badge: HTMLElement;
    /** Status strip for the opened file. */
    state: HTMLElement;
    detail: HTMLElement;
    /** Signing controls for the export. */
    signRow: HTMLElement;
    signToggle: HTMLInputElement;
    signNote: HTMLElement;
}

export interface CredentialsPanelOptions extends Elements {
    /** Called when the user turns signing on or off. */
    onSignChange: (enabled: boolean) => void;
}

export class CredentialsPanel {
    private readonly ui: Elements;
    private readonly onSignChange: (enabled: boolean) => void;

    private support: CredentialSupport = { available: false };
    private signer: SignerDescription | null = null;
    private signerProblem: string | null = null;
    private report: CredentialReport | null = null;
    private thumbnail: string | null = null;
    private sourceFormat = '';
    private outputFormat = '';
    private wanted = true;

    constructor(options: CredentialsPanelOptions) {
        const { onSignChange, ...ui } = options;
        this.ui = ui;
        this.onSignChange = onSignChange;

        this.ui.signToggle.addEventListener('change', () => {
            this.wanted = this.ui.signToggle.checked;
            this.onSignChange(this.signingEnabled);
            this.renderSigning();
        });
    }

    /** What the engine reported it can do, from `capabilities()`. */
    setSupport(support: CredentialSupport): void {
        this.support = support;
        this.render();
    }

    /**
     * Who the claim-signer says it is, or why it could not be reached.
     *
     * Both nulls means no signer is configured, which is a supported
     * deployment: the editor exports without a credential and says so.
     */
    setSigner(signer: SignerDescription | null, problem: string | null): void {
        this.signer = signer;
        this.signerProblem = problem;
        this.render();
    }

    /** A file was opened. */
    setSource(source: SourceInfo | null): void {
        this.report = source?.credentials ?? null;
        this.thumbnail = source?.credentialThumbnail ?? null;
        this.sourceFormat = source?.format ?? '';

        // Opening a file that already carries a credential is the one case
        // where the panel is worth interrupting for: the user should see the
        // provenance without going looking for it.
        if (this.report) this.ui.panel.open = true;
        this.render();
    }

    /** The chosen export format changed. */
    setOutputFormat(format: string): void {
        this.outputFormat = format;
        this.render();
    }

    /** Whether the next export should be signed. */
    get signingEnabled(): boolean {
        return this.wanted && this.canSign;
    }

    /**
     * Whether signing is possible at all: the build supports it, the output
     * format can carry a manifest, and a claim-signer answered.
     *
     * The last of those is the one that changed when the signing key left the
     * browser. Without a Backend subsystem there is no key anywhere, so there
     * is nothing to offer.
     */
    private get canSign(): boolean {
        return (
            this.support.available === true &&
            this.signer !== null &&
            (this.support.formats ?? []).includes(this.outputFormat)
        );
    }

    private render(): void {
        this.renderState();
        this.renderSigning();
    }

    /* --------------------------------------------------------------------
       What the opened file carries
       -------------------------------------------------------------------- */

    private renderState(): void {
        const { state, detail, badge } = this.ui;
        state.className = 'cred-state';
        detail.replaceChildren();

        if (!this.sourceFormat) {
            badge.hidden = true;
            state.classList.add('is-idle');
            state.replaceChildren(line('Open an image to check it for Content Credentials.'));
            return;
        }

        // Reading a manifest means finding it at a known offset and hashing the
        // bytes around it, which is defined per container format. This build
        // implements JPEG. Saying so beats an ambiguous "none found", which
        // would imply the file had been checked and come up clean.
        if (!isJpeg(this.sourceFormat)) {
            badge.hidden = true;
            state.classList.add('is-idle');
            state.replaceChildren(
                line(`Content Credentials are read from JPEG. This file is ${this.sourceFormat.toUpperCase()}.`),
            );
            return;
        }

        if (!this.report) {
            badge.hidden = true;
            state.classList.add('is-idle');
            state.replaceChildren(
                line('No Content Credentials in this file.'),
                line('Nothing here records where it came from.', 'cred-sub'),
            );
            return;
        }

        badge.hidden = false;
        badge.textContent = this.report.valid ? 'verified' : 'failed';
        badge.classList.toggle('is-bad', !this.report.valid);
        state.classList.add(this.report.valid ? 'is-good' : 'is-bad');

        state.replaceChildren(
            line(
                this.report.valid
                    ? 'Content Credentials found, and they check out.'
                    : 'Content Credentials found, but they do not check out.',
                'cred-headline',
            ),
            line(
                this.report.valid
                    ? 'The image is unchanged since it was signed.'
                    : 'This image does not match what was signed. Treat it as altered.',
                'cred-sub',
            ),
        );

        detail.append(this.renderManifest(this.report.active, this.report));
        if (this.report.chain.length > 1) {
            detail.append(this.renderChain(this.report));
        }
    }

    private renderManifest(manifest: CredentialManifest, report: CredentialReport): HTMLElement {
        const wrap = document.createElement('div');
        wrap.className = 'cred-manifest';

        const head = document.createElement('div');
        head.className = 'cred-head';
        if (this.thumbnail) {
            const image = document.createElement('img');
            image.className = 'cred-thumb';
            image.src = this.thumbnail;
            image.alt = 'Thumbnail recorded in the credential';
            head.append(image);
        }
        const headText = document.createElement('div');
        headText.className = 'cred-head-text';
        headText.append(
            line(manifest.title || 'Untitled', 'cred-title'),
            line(`Produced by ${manifest.generator}`, 'cred-sub'),
        );
        head.append(headText);
        wrap.append(head);

        // Identity, stated separately from integrity and never as a bare tick.
        // Three states, not two: trusted, not checked, and checked-and-failed.
        const signature = manifest.signature;
        const signer =
            signature.subjectOrganisation || signature.subject || 'an unnamed signer';
        wrap.append(field('Signed by', signer));

        if (signature.trusted) {
            wrap.append(field('Vouched for by', signature.trustAnchor, 'is-good'));
        } else if (wasCheckedAgainstTrustList(manifest)) {
            wrap.append(
                field(
                    'Vouched for by',
                    `${signature.issuer || 'an unknown issuer'} — not on the trust list`,
                    'is-bad',
                ),
            );
        } else {
            wrap.append(
                field(
                    'Vouched for by',
                    `${signature.issuer || 'an unknown issuer'} — not checked against any trust list`,
                    'is-caution',
                ),
            );
        }

        // The Assurance Level and the Conforming Products List record come
        // straight out of the certificate. They are the two facts that separate
        // a conformant Generator Product from anything that can emit CBOR, and
        // showing them beats any wording this panel could invent.
        if (signature.assuranceLevel !== null) {
            wrap.append(
                field(
                    'Conformance',
                    `C2PA Assurance Level ${signature.assuranceLevel}${
                        signature.cplRecordId ? ` · CPL ${signature.cplRecordId}` : ''
                    }`,
                ),
            );
        }

        wrap.append(
            field(
                'Signature',
                signature.timeStamped
                    ? `${signature.algorithm}, time-stamped ${formatWhen(signature.timeStamp)}${
                          signature.timeStampAuthority ? ` by ${signature.timeStampAuthority}` : ''
                      }`
                    : `${signature.algorithm}, no trusted time-stamp`,
                signature.timeStamped ? '' : 'is-caution',
            ),
        );
        if (!signature.timeStamped && signature.notAfter) {
            wrap.append(
                line(
                    `Without one, this credential stops validating when the signing certificate expires on ${formatWhen(
                        signature.notAfter,
                    )}.`,
                    'cred-sub',
                ),
            );
        }

        if (manifest.actions.length) {
            wrap.append(subheading('What was done'));
            const list = document.createElement('ol');
            list.className = 'cred-actions';
            for (const action of manifest.actions) {
                const item = document.createElement('li');
                const name = document.createElement('span');
                name.className = 'cred-action-name';
                name.textContent = actionLabel(action.action);
                item.append(name);
                if (action.description) {
                    const detail = document.createElement('span');
                    detail.className = 'cred-action-detail';
                    detail.textContent = action.description;
                    item.append(detail);
                }
                item.title = `${action.action}${action.when ? ` · ${formatWhen(action.when)}` : ''}`;
                list.append(item);
            }
            wrap.append(list);
        }

        for (const ingredient of manifest.ingredients) {
            wrap.append(
                field(
                    'Made from',
                    `${ingredient.title || 'an earlier image'}${
                        ingredient.hasManifest ? ' (which had its own credential)' : ''
                    }`,
                ),
            );
        }

        // Every check, named by its specification status code. A viewer that
        // only says "valid" gives a reader no way to tell which guarantee they
        // are getting, and these codes are the vocabulary the spec defines for
        // exactly that.
        wrap.append(subheading('Checks'));
        const checks = document.createElement('ul');
        checks.className = 'cred-checks';
        const status = manifest.status;
        for (const entry of status.failure) checks.append(check('bad', entry.code, entry.explanation));
        for (const entry of status.success) checks.append(check('good', entry.code, entry.explanation));
        for (const entry of status.informational) {
            checks.append(check('info', entry.code, entry.explanation));
        }
        wrap.append(checks);

        wrap.append(field('Credential size', formatBytes(report.storeLen)));
        return wrap;
    }

    private renderChain(report: CredentialReport): HTMLElement {
        const wrap = document.createElement('div');
        wrap.className = 'cred-manifest';
        wrap.append(subheading(`Provenance chain (${report.chain.length} manifests)`));

        const list = document.createElement('ol');
        list.className = 'cred-chain';
        for (const manifest of report.chain) {
            const item = document.createElement('li');
            const failed = manifest.status.failure.length > 0;
            item.className = failed ? 'is-bad' : 'is-good';
            item.append(
                line(manifest.title || manifest.label, 'cred-action-name'),
                line(
                    `${manifest.generator} · ${manifest.actions.length} action${
                        manifest.actions.length === 1 ? '' : 's'
                    }`,
                    'cred-action-detail',
                ),
            );
            list.append(item);
        }
        wrap.append(list);
        return wrap;
    }

    /* --------------------------------------------------------------------
       Signing the export
       -------------------------------------------------------------------- */

    private renderSigning(): void {
        const { signRow, signToggle, signNote } = this.ui;

        if (!this.support.available) {
            signRow.hidden = true;
            signNote.className = 'cred-note';
            signNote.textContent = 'This build cannot write Content Credentials.';
            return;
        }

        // No claim-signer is a supported deployment, not a fault: the signing
        // key lives in the Backend subsystem, and the static build has none.
        // Saying which of the two happened is the whole point of this branch.
        if (!this.signer) {
            signRow.hidden = true;
            signNote.className = 'cred-note';
            signNote.replaceChildren(
                line(
                    this.signerProblem
                        ? `The signing service could not be reached: ${this.signerProblem}`
                        : 'This deployment has no signing service, so exports carry no Content Credentials.',
                ),
                line(
                    'The signing key is deliberately not in your browser — see conformance/README.md.',
                    'cred-sub',
                ),
            );
            return;
        }

        signRow.hidden = false;
        signToggle.checked = this.signingEnabled;
        signToggle.disabled = !this.canSign;
        signRow.classList.toggle('is-disabled', !this.canSign);

        // The brief was explicit that other formats keep working as an ordinary
        // editor, so this is a note about scope rather than a warning.
        if (!this.canSign) {
            signNote.textContent = this.outputFormat
                ? `Credentials are written to JPEG only. ${this.outputFormat.toUpperCase()} exports normally, without one.`
                : 'Credentials are written to JPEG only.';
            signNote.className = 'cred-note';
            return;
        }

        if (!this.wanted) {
            signNote.textContent = 'The exported JPEG will carry no record of where it came from.';
            signNote.className = 'cred-note';
            return;
        }

        const signer = this.signer;
        const conformant = signer.assuranceLevel !== null && signer.claimSigningEku;
        signNote.className = conformant ? 'cred-note is-good' : 'cred-note is-caution';
        signNote.replaceChildren(
            line(
                `Signed as ${signer.organisation || signer.commonName}, by ${signer.issuer}.`,
            ),
            line(
                conformant
                    ? `C2PA Assurance Level ${signer.assuranceLevel}${
                          signer.timeStamped ? ', with a trusted time-stamp' : ', without a time-stamp'
                      }. The claim is signed by the service; the image never leaves this tab.`
                    : 'This certificate was not issued under the C2PA Certificate Policy, so validators will not recognise it as coming from a conforming Generator Product.',
                'cred-sub',
            ),
        );
    }
}

/* -------------------------------------------------------------------------
   Small builders. Everything is created as DOM rather than assembled as an
   HTML string: a filename, a signer's name and an action description all come
   from a file the user did not write, and this panel exists to be trusted.
   ------------------------------------------------------------------------- */

function line(text: string, className?: string): HTMLElement {
    const node = document.createElement('p');
    if (className) node.className = className;
    node.textContent = text;
    return node;
}

function subheading(text: string): HTMLElement {
    const node = document.createElement('h4');
    node.className = 'cred-subheading';
    node.textContent = text;
    return node;
}

function field(label: string, value: string, className = ''): HTMLElement {
    const row = document.createElement('div');
    row.className = `cred-field ${className}`.trim();
    const key = document.createElement('span');
    key.className = 'cred-key';
    key.textContent = label;
    const val = document.createElement('span');
    val.className = 'cred-value';
    val.textContent = value;
    row.append(key, val);
    return row;
}

function check(kind: 'good' | 'bad' | 'info', code: string, explanation: string): HTMLElement {
    const item = document.createElement('li');
    item.className = `is-${kind}`;
    const name = document.createElement('code');
    name.textContent = code;
    const text = document.createElement('span');
    text.textContent = explanation;
    item.append(name, text);
    return item;
}

/**
 * Whether a trust list was consulted for this manifest.
 *
 * Derived from the status codes rather than from the app's own configuration,
 * because the report is the record of what the validator actually did: the
 * engine files `signingCredential.untrusted` as *informational* when no list
 * was supplied and as a *failure* when one was and the chain missed it. Reading
 * it back this way means the panel cannot drift out of step with the validator.
 */
function wasCheckedAgainstTrustList(manifest: CredentialManifest): boolean {
    return !manifest.status.informational.some(
        (entry) => entry.code === 'signingCredential.untrusted',
    );
}

function isJpeg(format: string): boolean {
    return format.toLowerCase() === 'jpeg' || format.toLowerCase() === 'jpg';
}
