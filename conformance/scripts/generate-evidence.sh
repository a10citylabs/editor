#!/usr/bin/env bash
#
# Produce the crJSON evidence the C2PA Conformance Program asks for.
#
# From the Program document: "Generator Product applicants must provide sample
# output media files of every asserted generate and validate media type […]
# along with their associated .crjson or .json files for analysis", and from the
# Additional Conformance Requirements: "Applicant SHALL provide validation
# results in crJSON format for a set of test inputs provided by the Conformance
# Program."
#
# Two kinds of asset, because the Program asks for both:
#
#   * ones this product *generated*, showing what its manifests look like
#   * ones this product *validated*, showing what its validator reports
#
# Until the Program supplies its asset library, the same signed files serve as
# both. Point `--asset-dir` at the Program's assets when they arrive; nothing
# else changes.
#
# Usage:  ./conformance/scripts/generate-evidence.sh [asset-dir]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

out="$root/conformance/evidence"
assets="${1:-$out/assets}"
mkdir -p "$out/crjson" "$assets"

echo "==> building the harness"
cargo build --release -p c2pa-harness --quiet

if [ -z "${1:-}" ]; then
    echo "==> generating sample assets"
    # `--nocapture` so the fixture writer's paths land in the log, and a single
    # test so the run is quick.
    cargo test --release -p imagecore --test evidence -- --nocapture --ignored
fi

echo "==> validating and writing crJSON"
# The validation time is derived from the test certificate rather than fixed,
# so the evidence stays reproducible after the test PKI is regenerated. With
# the Program's own assets, pass the time the Program specifies.
validation_time="$(
    cargo run --release --quiet -p c2pa-harness -- --help >/dev/null 2>&1
    python3 - <<'PY'
import datetime, pathlib, re, subprocess
pem = pathlib.Path("conformance/test-credentials/c2pa-test-claim-signer.pem")
text = subprocess.run(
    ["openssl", "x509", "-in", str(pem), "-noout", "-startdate"],
    capture_output=True, text=True, check=True,
).stdout
stamp = text.split("=", 1)[1].strip()
at = datetime.datetime.strptime(stamp, "%b %d %H:%M:%S %Y %Z").replace(
    tzinfo=datetime.timezone.utc
) + datetime.timedelta(days=1)
print(at.strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
echo "    validation time: $validation_time"

./target/release/c2pa-harness batch \
    --asset-dir "$assets" \
    --output-dir "$out/crjson" \
    --trust-list conformance/test-credentials/c2pa-test-trust-list.pem \
    --tsa-trust-list conformance/test-credentials/c2pa-test-tsa-trust-list.pem \
    --validation-time "$validation_time"

echo "==> wrote $(ls -1 "$out/crjson" | wc -l) crJSON document(s) into $out/crjson"
