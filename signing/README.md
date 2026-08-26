# Signing credentials

These files sign the Content Credentials this editor writes. **The private key
in this directory is public.** That is deliberate, and this file explains why,
because "the key is in the repo" usually means someone made a mistake.

```
demo-root-ca.pem   self-signed P-256 root, CA:TRUE  (never leaves the repo)
demo-signer.pem    P-256 leaf signed by that root   (goes into x5chain)
demo-signer.key    PKCS#8 private key for the leaf  (compiled into the wasm)
generate.sh        regenerates all three
```

## Why the key is in the open

The whole point of this app is that images never leave the tab. Signing happens
in the browser, so the signing key has to *be* in the browser. Anything shipped
to a browser is readable by whoever receives it — bundling, minifying or
fetching it at runtime changes how long it takes to find, not whether it can be
found.

So there is no arrangement in which a client-side claim generator holds a secret
signing key. The choice is not "hidden key vs. exposed key", it is "exposed key,
honestly labelled" vs. "exposed key, dishonestly labelled". This app picks the
first and says so in the UI: every credential it writes is marked as coming from
an untrusted demo signer, and the certificate's own subject reads
`OU = Untrusted demonstration signer`.

C2PA is built for exactly this. Trust in a manifest comes from the signing
certificate chaining to a trust anchor a validator recognises — in practice the
[C2PA Trust List](https://opensource.contentauthenticity.org/docs/verify-known-list).
This root is not on it and will never be. A validator will therefore report
these images as *"signed, contents intact, signer not known"*. That is the
correct answer, and it is a genuinely useful one: the hard binding still proves
the pixels have not been touched since signing, and the actions still describe
what the editor did. Only the identity claim is unverifiable.

## What GitHub secrets are and are not good for

Short answer: **they cannot make a browser-side signing key secret, and this
repository does not pretend otherwise.** A GitHub Actions secret is decrypted
inside the Actions runner. Whatever the runner bakes into `dist/` is served to
every visitor. Moving the key from the repository into a secret moves *where the
build reads it from*; it does not stop the built artefact from containing it.

They are still wired up, for one narrow thing that is real: keeping a key out of
public git history. If you fork this and want the deployed site signed by a
different key — one you can rotate, one that isn't in every clone and every
mirror of the repo — set two repository secrets:

| Secret | Contents |
|---|---|
| `C2PA_SIGNING_CERT` | PEM certificate chain, leaf first |
| `C2PA_SIGNING_KEY`  | PKCS#8 PEM private key for the leaf |

`crates/imagecore/build.rs` reads those two environment variables and compiles
whatever it finds into the engine. If either is missing it falls back to the
demo files here, so local builds and forks without secrets keep working. The
deploy workflow passes them through; CI does not, so pull requests always build
against the committed demo key.

Rotating the secret still only rotates a *published* key. Treat it as "this
build's identity", never as a credential.

### If you want credentials people can actually trust

Sign somewhere the key can stay private. Two designs fit this app without
giving up its no-upload property:

- **Remote signing.** The browser builds the claim and sends only the hash of
  it to a signing endpoint, which returns a signature. The image itself never
  leaves the tab — only 32 bytes of hash do. This is what the C2PA
  [remote signing](https://opensource.contentauthenticity.org/docs/signing/)
  flow is for, and the code here is already shaped for it: `sign_claim` in
  `crates/imagecore/src/c2pa/cose.rs` takes the bytes to be signed and returns
  a signature, so swapping the local key for a network round-trip is a change
  at one call site.
- **Per-user certificates.** Let a signed-in user supply their own certificate
  and key, held only for the session. Then the identity in the credential is
  theirs, and the app never holds a key at all.

Both are out of scope for a proof of concept. Neither changes any of the
manifest-building code — only where the 64 signature bytes come from.

## Certificate profile

`generate.sh` follows the certificate profile in C2PA 2.2 §14.5.1:

- ECDSA on `prime256v1`, signed with SHA-256, giving `ES256` COSE signatures
- v3 certificates, no `issuerUniqueID` / `subjectUniqueID`
- Key Usage present and critical; the leaf asserts `digitalSignature` only, and
  does not assert `keyCertSign`
- Extended Key Usage present, non-empty and critical on the leaf:
  `emailProtection` (1.3.6.1.5.5.7.3.4), one of the EKUs §14.4.1 names for
  C2PA signing. `anyExtendedKeyUsage` is absent, as required
- Basic Constraints `cA` asserted on the root, explicitly not on the leaf
- Subject Key Identifier on both; Authority Key Identifier on the leaf

The chain is two certificates deep, so `x5chain` carries the leaf alone — the
spec says to include the signer and any intermediates but not the trust anchor.
The root sits here only so the app can name the issuer in its UI.

The certificates are dated 20 years out. That looks careless and isn't: a
manifest with no RFC 3161 time-stamp stops validating the moment its signing
certificate expires, and this demo has no Time Stamp Authority. A one-year
certificate would quietly invalidate every image the app had ever signed. A
production deployment should get a time-stamp at signing time and use a
normal-lived certificate instead.

## Regenerating

```sh
./signing/generate.sh
```

Requires OpenSSL 3. It prints the leaf's extensions and verifies the chain
before finishing. Nothing caches the old key, so rebuild the engine afterwards
(`npm run build:wasm`) — and note that images signed with the previous key stay
verifiable only for as long as someone keeps that certificate around.
