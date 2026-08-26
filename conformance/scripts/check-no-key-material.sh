#!/usr/bin/env bash
#
# Prove the Edge subsystem holds no key.
#
# The single change that makes Assurance Level 1 reachable for this product is
# that the claim signing key left the browser. That is easy to assert in a
# document and easy to undo by accident, so it is checked mechanically instead.
#
# Three things are verified, in increasing order of how much they would catch:
#
#   1. The `test-pki` feature — the only thing that compiles a private key into
#      `imagecore` — is not enabled by default and is not reachable from a
#      release build of the library.
#   2. No private-key *type* is linked into the wasm build. `p256/pkcs8` and
#      `p256/pem` are what would pull one in; a plain `cargo tree` shows whether
#      they are on.
#   3. The built `.wasm` contains no PEM private-key header and none of the
#      bytes of the test signing key.
#
# The third is the one that would catch a mistake nobody anticipated, so it runs
# against the artefact that actually ships rather than against the manifest.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

fail() {
    echo "check-no-key-material: $1" >&2
    exit 1
}

echo "==> the test PKI feature is off by default"
if cargo metadata --no-deps --format-version 1 \
    | python3 -c '
import json, sys
crate = next(p for p in json.load(sys.stdin)["packages"] if p["name"] == "imagecore")
default = crate["features"].get("default", [])
sys.exit(0 if "test-pki" in default else 1)
'; then
    fail "imagecore enables test-pki by default; a release build would carry a private key"
fi

echo "==> no private-key handling is linked into the library build"
# `no-dev` matters: the test suite legitimately links the private-key readers,
# and it is only their presence in the *normal* graph - the one wasm-pack
# builds - that would put a key in the browser.
if cargo tree -p imagecore --target wasm32-unknown-unknown --edges features,no-dev 2>/dev/null \
    | grep -qE 'p256 feature "(pkcs8|pem)"'; then
    fail "the wasm build links p256's pkcs8/pem features, which exist only to read private keys"
fi

echo "==> the built module contains no key material"
wasm="apps/editor/src/wasm/imagecore_bg.wasm"
if [ ! -f "$wasm" ]; then
    echo "    $wasm is not built; building it"
    npm run --silent build:wasm
fi

for needle in "BEGIN PRIVATE KEY" "BEGIN EC PRIVATE KEY" "BEGIN RSA PRIVATE KEY"; do
    if grep -qa "$needle" "$wasm"; then
        fail "the wasm module contains '$needle'"
    fi
done

# And the exact bytes of the test key, in case a future change embeds it in
# some form the string search above would miss.
key="conformance/test-credentials/c2pa-test-claim-signer.key"
if [ -f "$key" ]; then
    python3 - "$wasm" "$key" <<'PY'
import base64, sys, pathlib

wasm = pathlib.Path(sys.argv[1]).read_bytes()
pem = pathlib.Path(sys.argv[2]).read_text()
body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
der = base64.b64decode(body)

for name, needle in (("DER", der), ("base64", body.encode())):
    if needle and needle in wasm:
        print(f"check-no-key-material: the wasm module contains the test signing key ({name})",
              file=sys.stderr)
        raise SystemExit(1)
PY
fi

echo "==> the Edge subsystem holds no key material"
