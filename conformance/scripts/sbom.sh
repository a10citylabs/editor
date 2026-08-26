#!/usr/bin/env bash
#
# Generate a Software Bill of Materials for every component of the Generator
# Product Target of Evaluation.
#
# The C2PA Generator Product Security Requirements, objectives O.3 and O.4 at
# Assurance Level 1:
#
#   "Applicant SHALL ensure a Software Composition Analysis (SCA) or Software
#    Bill of Materials (SBOM) analysis is performed to detect vulnerabilities
#    from the NIST National Vulnerability Database (NVD) in the Claim
#    Generator [O.3] / in all software in the GP TOE that processes or modifies
#    the Digital Content and/or assertions [O.4]."
#
# O.4 is the wider of the two and is what fixes the scope here: the image
# pipeline touches the pixels, the claim generator builds the assertions, and
# the claim-signer holds the key — so all three are in, and so is the browser
# app that drives them.
#
# Output is CycloneDX, one document per component plus a merged one, written to
# `conformance/evidence/sbom/`. CycloneDX is on the Conformance Program's list
# of industry-adopted reporting formats and is what `cargo-audit` and `osv-
# scanner` both read.
#
# Usage:  ./conformance/scripts/sbom.sh [output-dir]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${1:-$root/conformance/evidence/sbom}"
mkdir -p "$out"

echo "==> Rust components (cargo-cyclonedx)"
if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "    installing cargo-cyclonedx"
    cargo install cargo-cyclonedx --locked --quiet
fi

# One document per crate rather than one for the workspace: the Conforming
# Products List records a Generator Product, and an assessor reading the
# evidence needs to see which dependencies reach the signing key and which only
# reach the pixels.
#
# `cargo cyclonedx` writes each document beside its own Cargo.toml and has no
# output-directory option, so the files are collected afterwards rather than
# redirected. `--all` means the full transitive graph; `--top-level` would list
# only direct dependencies, which is not what an NVD scan needs to cover.
(
    cd "$root"
    cargo cyclonedx --format json --all --spec-version 1.5 --quiet
)

while IFS= read -r document; do
    mv "$document" "$out/$(basename "$document")"
done < <(find "$root/crates" "$root/services" -maxdepth 2 -name '*.cdx.json')

echo "==> Web application (npm)"
if [ -f "$root/package-lock.json" ]; then
    (
        cd "$root"
        # `npm sbom` needs an installed tree to resolve the graph.
        [ -d node_modules ] || npm ci --silent
        npm sbom --sbom-format cyclonedx --sbom-type application \
            > "$out/editor-web.cdx.json"
    )
fi

echo "==> wrote SBOMs into $out"
ls -1 "$out"
