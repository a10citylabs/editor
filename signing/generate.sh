#!/usr/bin/env bash
#
# Regenerate the demo signing chain used by the browser claim generator.
#
# Everything this produces is PUBLIC by design: the private key ships inside a
# static web app, so it is readable by anyone who opens the bundle. See
# README.md in this directory for why that is the honest design rather than a
# shortcut, and what the GitHub Actions secrets path does and does not buy.
#
# Usage:  ./generate.sh [output-dir]
#
# The certificate profile follows C2PA 2.2 section 14.5.1 ("Certificate
# Profile"):
#   * ECDSA on prime256v1, signed with ES256
#   * v3 certificates
#   * Key Usage present and critical; leaf asserts digitalSignature only
#   * Extended Key Usage present and non-empty on the leaf; emailProtection
#     (1.3.6.1.5.5.7.3.4) is one of the EKUs the spec names for C2PA signing
#   * anyExtendedKeyUsage (2.5.29.37.0) absent
#   * Basic Constraints cA asserted on the root, not asserted on the leaf
#   * Authority Key Identifier on the leaf (it is not self-signed)
#   * Subject Key Identifier on both
set -euo pipefail

out="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
mkdir -p "$out"
cfg="$(mktemp -d)"
trap 'rm -rf "$cfg"' EXIT

# Long validity on purpose. A C2PA manifest without an RFC 3161 time-stamp
# stops validating the moment its signing certificate expires, and this demo
# has no Time Stamp Authority, so a short-lived certificate would silently
# break every image the app has ever signed.
days=7300

cat > "$cfg/root.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = IN
O  = A10city Labs
CN = A10city Image Editor Demo Root CA
[v3]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
EOF

cat > "$cfg/leaf.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = IN
O  = A10city Labs
OU = Untrusted demonstration signer
CN = A10city Image Editor Demo Signer
[v3]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, emailProtection
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

echo "==> root key + self-signed root certificate"
openssl ecparam -name prime256v1 -genkey -noout -out "$cfg/root.key"
openssl req -new -x509 -key "$cfg/root.key" -sha256 -days "$days" \
    -config "$cfg/root.cnf" -extensions v3 -out "$out/demo-root-ca.pem"

echo "==> leaf key + certificate signed by the root"
openssl ecparam -name prime256v1 -genkey -noout -out "$cfg/leaf.ec.key"
# The engine parses PKCS#8, which is the modern default and what every other
# toolchain hands you. `ecparam` still emits SEC1, so convert.
openssl pkcs8 -topk8 -nocrypt -in "$cfg/leaf.ec.key" -out "$out/demo-signer.key"
openssl req -new -key "$cfg/leaf.ec.key" -config "$cfg/leaf.cnf" -out "$cfg/leaf.csr"
openssl x509 -req -in "$cfg/leaf.csr" -CA "$out/demo-root-ca.pem" -CAkey "$cfg/root.key" \
    -CAcreateserial -sha256 -days "$days" \
    -extfile "$cfg/leaf.cnf" -extensions v3 -out "$out/demo-signer.pem"

# The x5chain COSE header carries the signer plus every intermediate, but not
# the trust anchor (C2PA 2.2 section 13.2.2). With a two-certificate chain that
# is the leaf alone; the root is kept beside it only so the app can show who
# issued the signer.
cat "$out/demo-signer.pem" > "$cfg/chain.pem"

echo "==> verify"
openssl verify -CAfile "$out/demo-root-ca.pem" "$out/demo-signer.pem"
openssl x509 -in "$out/demo-signer.pem" -noout -text | sed -n '/X509v3/,/Signature Algorithm/p'

rm -f "$out/demo-root-ca.srl"
echo "==> wrote demo-root-ca.pem, demo-signer.pem, demo-signer.key into $out"
