#!/usr/bin/env bash
#
# Generate the *test* PKI the conformance harness and the local claim-signer
# run against.
#
# Nothing here is a production credential and nothing here is trusted by any
# validator outside this repository. Production claim signing certificates come
# from a Certification Authority on the C2PA Trust List — see
# `conformance/enrolment-runbook.md`. What this script exists for is to produce
# certificates that are shaped *exactly* like the ones a CA will issue, so that
# every code path the real certificate will exercise is exercised in CI too:
# the c2pa-kp-claimSigning EKU, the assurance-level extension, the CPL record
# id, the 366-day ceiling, and a time-stamping authority to test against.
#
# Profiles implemented, from the C2PA Certificate Policy v0.2, "Certificate
# Profiles":
#
#   * C2PA Claim Signing Root CA
#   * C2PA Claim Signing Issuing CA
#   * C2PA Claim Signing Leaf — Assurance Level 1
#   * A time-stamping authority chain, for the TSA Trust List
#
# Usage:  ./generate.sh [output-dir]
set -euo pipefail

out="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- OIDs from the C2PA private arc (1.3.6.1.4.1.62558) ----------------------
OID_CP="1.3.6.1.4.1.62558.1.1"        # c2pa-certificate-policy
OID_EKU_CLAIM="1.3.6.1.4.1.62558.2.1" # c2pa-kp-claimSigning
OID_AL="1.3.6.1.4.1.62558.3"          # id-c2pa-al
OID_AL1="1.3.6.1.4.1.62558.3.10"      # c2pa-assuranceLevel-1
OID_CPL="1.3.6.1.4.1.62558.4"         # c2pa-cpl-record

# The Conforming Products List record id is a UUID the Conformance Program
# assigns when the product is listed. Until this product is listed there is no
# real one, so the test chain carries the nil UUID: it is the same shape and
# obviously not a real record.
CPL_RECORD_ID="${C2PA_CPL_RECORD_ID:-00000000-0000-0000-0000-000000000000}"

# Assurance Level 1 caps leaf validity at 366 days. Using the real ceiling in
# the test PKI is deliberate: it means the expiry handling, and the time-stamp
# that has to outlive the certificate, are exercised rather than postponed by a
# twenty-year certificate that hides both.
LEAF_DAYS=366
CA_DAYS=3650

echo "==> C2PA claim signing root CA"
cat > "$work/root.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = IN
O  = A10city Labs
CN = A10city C2PA Test Root CA
[v3]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
certificatePolicies    = $OID_CP
EOF
openssl ecparam -name prime256v1 -genkey -noout -out "$work/root.key"
openssl req -new -x509 -key "$work/root.key" -sha256 -days "$CA_DAYS" \
    -config "$work/root.cnf" -extensions v3 -out "$out/c2pa-test-root-ca.pem"

echo "==> C2PA claim signing issuing CA"
cat > "$work/issuing.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = IN
O  = A10city Labs
CN = A10city C2PA Test Claim Signing CA
[v3]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
certificatePolicies    = $OID_CP
extendedKeyUsage       = $OID_EKU_CLAIM, emailProtection
EOF
openssl ecparam -name prime256v1 -genkey -noout -out "$work/issuing.key"
openssl req -new -key "$work/issuing.key" -config "$work/issuing.cnf" -out "$work/issuing.csr"
openssl x509 -req -in "$work/issuing.csr" \
    -CA "$out/c2pa-test-root-ca.pem" -CAkey "$work/root.key" -CAcreateserial \
    -sha256 -days "$CA_DAYS" -extfile "$work/issuing.cnf" -extensions v3 \
    -out "$out/c2pa-test-issuing-ca.pem"

echo "==> C2PA claim signing leaf, assurance level 1"
# Subject must match the Conforming Products List entry for the product. The
# claim generator reads O and CN back out of this certificate and shows them,
# so what goes in here is what a viewer sees.
cat > "$work/leaf.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = IN
O  = A10city Labs
CN = A10city Image Editor
[v3]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
extendedKeyUsage       = $OID_EKU_CLAIM, emailProtection
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
certificatePolicies    = $OID_CP
authorityInfoAccess    = OCSP;URI:http://ocsp.test.invalid/c2pa, caIssuers;URI:http://pki.test.invalid/c2pa-issuing-ca.der
$OID_AL                = ASN1:OID:$OID_AL1
$OID_CPL               = ASN1:UTF8String:$CPL_RECORD_ID
EOF
openssl ecparam -name prime256v1 -genkey -noout -out "$work/leaf.ec.key"
# The signer parses PKCS#8, which is what every other toolchain hands you.
# `ecparam` still emits SEC1, so convert.
openssl pkcs8 -topk8 -nocrypt -in "$work/leaf.ec.key" -out "$out/c2pa-test-claim-signer.key"
openssl req -new -key "$work/leaf.ec.key" -config "$work/leaf.cnf" -out "$work/leaf.csr"
openssl x509 -req -in "$work/leaf.csr" \
    -CA "$out/c2pa-test-issuing-ca.pem" -CAkey "$work/issuing.key" -CAcreateserial \
    -sha256 -days "$LEAF_DAYS" -extfile "$work/leaf.cnf" -extensions v3 \
    -out "$out/c2pa-test-claim-signer.pem"

# x5chain carries the signer and every intermediate, but never the trust anchor
# (C2PA 2.2 section 13.2.2).
cat "$out/c2pa-test-claim-signer.pem" "$out/c2pa-test-issuing-ca.pem" \
    > "$out/c2pa-test-claim-signer-chain.pem"

echo "==> time-stamping authority"
cat > "$work/tsa-root.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = IN
O  = A10city Labs
CN = A10city C2PA Test TSA Root CA
[v3]
basicConstraints     = critical, CA:TRUE, pathlen:0
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
openssl ecparam -name prime256v1 -genkey -noout -out "$work/tsa-root.key"
openssl req -new -x509 -key "$work/tsa-root.key" -sha256 -days "$CA_DAYS" \
    -config "$work/tsa-root.cnf" -extensions v3 -out "$out/tsa-test-root-ca.pem"

# RFC 3161 section 2.3: the TSA's certificate must carry the timeStamping EKU,
# and it must be critical and the only EKU present.
cat > "$work/tsa.cnf" <<EOF
[req]
distinguished_name = dn
prompt             = no
[dn]
C  = IN
O  = A10city Labs
CN = A10city C2PA Test Timestamp Authority
[v3]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, nonRepudiation
extendedKeyUsage       = critical, timeStamping
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF
openssl ecparam -name prime256v1 -genkey -noout -out "$work/tsa.ec.key"
openssl pkcs8 -topk8 -nocrypt -in "$work/tsa.ec.key" -out "$out/tsa-test-signer.key"
openssl req -new -key "$work/tsa.ec.key" -config "$work/tsa.cnf" -out "$work/tsa.csr"
openssl x509 -req -in "$work/tsa.csr" \
    -CA "$out/tsa-test-root-ca.pem" -CAkey "$work/tsa-root.key" -CAcreateserial \
    -sha256 -days "$CA_DAYS" -extfile "$work/tsa.cnf" -extensions v3 \
    -out "$out/tsa-test-signer.pem"

# --- trust lists -------------------------------------------------------------
# A C2PA Trust List is distributed as a bundle of PEM trust anchors. The test
# lists here stand in for the real ones the Conformance Program supplies, and
# the harness takes both as command-line inputs so the real ones can be dropped
# in without touching any code.
cat "$out/c2pa-test-root-ca.pem" > "$out/c2pa-test-trust-list.pem"
cat "$out/tsa-test-root-ca.pem" > "$out/c2pa-test-tsa-trust-list.pem"

echo "==> verify"
openssl verify -CAfile "$out/c2pa-test-root-ca.pem" \
    -untrusted "$out/c2pa-test-issuing-ca.pem" "$out/c2pa-test-claim-signer.pem"
openssl verify -CAfile "$out/tsa-test-root-ca.pem" "$out/tsa-test-signer.pem"

echo "==> claim signing leaf extensions"
openssl x509 -in "$out/c2pa-test-claim-signer.pem" -noout -text \
    | sed -n '/X509v3 extensions/,/Signature Algorithm/p'

rm -f "$out"/*.srl
echo "==> wrote the test PKI into $out"
