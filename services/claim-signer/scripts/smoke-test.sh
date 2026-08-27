#!/usr/bin/env bash
#
# Exercise a running claim-signer over HTTP: the two public endpoints, one
# authenticated signature, and the refusals that matter.
#
# Signing by hand is the awkward part of testing this service — the request is
# authenticated with an HMAC over the method, path, timestamp, nonce and a
# digest of the body, so `curl` alone cannot do it. That is what this is for.
#
#   ./services/claim-signer/scripts/smoke-test.sh \
#       --url https://sign.example.com --key-id dev --secret "$SECRET"
#
# The secret is the Base64 string from CLAIM_SIGNER_CLIENTS, or one minted by
# the application server's credential endpoint. Exit status is 0 when every
# check passed.
#
# Nothing here needs the keystore, the key-encryption key, or any access to the
# host: it is a black-box test, so the same invocation works against a service
# on localhost and against production.

set -euo pipefail

URL="http://127.0.0.1:8443"
KEY_ID=""
SECRET=""
INSECURE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="${2%/}"; shift 2 ;;
        --key-id) KEY_ID="$2"; shift 2 ;;
        --secret) SECRET="$2"; shift 2 ;;
        # For a service presenting a certificate your machine has no reason to
        # trust — a self-signed one used to exercise the TLS path locally.
        --insecure) INSECURE="--insecure"; shift ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option '$1'" >&2; exit 2 ;;
    esac
done

failures=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; failures=$((failures + 1)); }

get() { curl -sS $INSECURE -m 20 "$@"; }

echo "claim-signer smoke test against $URL"
echo

# ---------------------------------------------------------------------------
# The unauthenticated endpoints
# ---------------------------------------------------------------------------
echo "Public endpoints"

health="$(get "$URL/healthz" || true)"
if printf '%s' "$health" | grep -q '"status":"ok"'; then
    pass "GET /healthz — $(printf '%s' "$health" | tr -d '{}"' )"
else
    fail "GET /healthz did not answer ok: ${health:-<no response>}"
fi

identity="$(get "$URL/v1/identity" || true)"
if printf '%s' "$identity" | grep -q '"chainPem"'; then
    key_id_reported="$(printf '%s' "$identity" | sed -n 's/.*"keyId":"\([^"]*\)".*/\1/p')"
    algorithm="$(printf '%s' "$identity" | sed -n 's/.*"algorithm":"\([^"]*\)".*/\1/p')"
    not_after="$(printf '%s' "$identity" | sed -n 's/.*"notAfter":"\([^"]*\)".*/\1/p')"
    pass "GET /v1/identity — keyId=$key_id_reported algorithm=$algorithm notAfter=$not_after"

    # The two facts that separate a conforming Generator Product from anything
    # that can emit CBOR. A test credential has neither, and should say so
    # here rather than in someone else's validator.
    if printf '%s' "$identity" | grep -q '"assuranceLevel":[0-9]'; then
        level="$(printf '%s' "$identity" | sed -n 's/.*"assuranceLevel":\([0-9]*\).*/\1/p')"
        record="$(printf '%s' "$identity" | sed -n 's/.*"cplRecordId":"\([^"]*\)".*/\1/p')"
        pass "  certificate carries C2PA Assurance Level $level, CPL record ${record:-none}"
    else
        printf '  \033[33mnote\033[0m the certificate carries no c2pa-al extension (a test credential)\n'
    fi
else
    fail "GET /v1/identity did not return a certificate chain: ${identity:-<no response>}"
fi

if [ -z "$KEY_ID" ] || [ -z "$SECRET" ]; then
    echo
    echo "No --key-id/--secret given, so /v1/sign was not exercised."
    [ "$failures" -eq 0 ] || exit 1
    exit 0
fi

# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------
echo
echo "Signing"

# HMAC-SHA256(secret, method ‖ "\n" ‖ path ‖ "\n" ‖ ts ‖ "\n" ‖ nonce ‖ "\n" ‖ hex(SHA-256(body)))
# — matching services/claim-signer/src/auth.rs and apps/editor/src/signer.ts.
secret_hex="$(printf '%s' "$SECRET" | base64 -d | od -An -tx1 | tr -d ' \n')"

authorization() {
    local method="$1" path="$2" body="$3" ts="$4" nonce="$5"
    local digest mac
    digest="$(printf '%s' "$body" | openssl dgst -sha256 | awk '{print $NF}')"
    mac="$(printf '%s\n%s\n%s\n%s\n%s' "$method" "$path" "$ts" "$nonce" "$digest" \
        | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$secret_hex" -binary | base64 -w0)"
    printf 'C2PA-HMAC-SHA256 key=%s, ts=%s, nonce=%s, mac=%s' "$KEY_ID" "$ts" "$nonce" "$mac"
}

# Any non-empty bytes will do: the service signs what it is given, and this
# test is about the transport and the credential, not about claim structure.
BODY='{"toBeSigned":"VGhpcyBpcyBhIHNtb2tlIHRlc3Qu"}'
PATH_SIGN="/v1/sign"

post_sign() {
    local ts="$1" nonce="$2" auth
    auth="$(authorization POST "$PATH_SIGN" "$BODY" "$ts" "$nonce")"
    curl -sS $INSECURE -m 30 -o /tmp/claim-signer-smoke.$$ -w '%{http_code}' \
        -X POST "$URL$PATH_SIGN" \
        -H 'Content-Type: application/json' \
        -H "Authorization: $auth" \
        --data "$BODY"
}

now="$(date -u +%s)"
nonce="$(openssl rand -hex 16)"
code="$(post_sign "$now" "$nonce" || true)"
response="$(cat /tmp/claim-signer-smoke.$$ 2>/dev/null || true)"

if [ "$code" = "200" ] && printf '%s' "$response" | grep -q '"signature"'; then
    if printf '%s' "$response" | grep -q '"timestampToken"'; then
        pass "POST /v1/sign — signed and time-stamped"
    elif printf '%s' "$response" | grep -q '"timestampError"'; then
        why="$(printf '%s' "$response" | sed -n 's/.*"timestampError":"\([^"]*\)".*/\1/p')"
        printf '  \033[33mnote\033[0m signed, but no time-stamp: %s\n' "$why"
        pass "POST /v1/sign — signed"
    else
        printf '  \033[33mnote\033[0m signed, with no authority configured (CLAIM_SIGNER_TSA_URL unset)\n'
        pass "POST /v1/sign — signed"
    fi
else
    fail "POST /v1/sign answered $code: $response"
fi

# ---------------------------------------------------------------------------
# The refusals. A signing endpoint that only works is only half tested.
# ---------------------------------------------------------------------------
echo
echo "Refusals"

code="$(curl -sS $INSECURE -m 20 -o /dev/null -w '%{http_code}' -X POST "$URL$PATH_SIGN" \
    -H 'Content-Type: application/json' --data "$BODY" || true)"
[ "$code" = "401" ] && pass "no Authorization header → 401" \
    || fail "no Authorization header → $code, expected 401"

# The same nonce and timestamp a second time. The service remembers nonces for
# its skew window precisely so a captured request cannot be sent again.
code="$(post_sign "$now" "$nonce" || true)"
[ "$code" = "401" ] && pass "replayed nonce → 401" \
    || fail "replayed nonce → $code, expected 401"

# Outside the 120-second window.
code="$(post_sign "$((now - 600))" "$(openssl rand -hex 16)" || true)"
[ "$code" = "401" ] && pass "timestamp outside the window → 401" \
    || fail "stale timestamp → $code, expected 401"

# A key id nobody issued. Answers identically to a bad MAC on purpose, so the
# endpoint is not a way to enumerate valid key ids.
saved_key="$KEY_ID"; KEY_ID="definitely-not-a-client"
code="$(post_sign "$(date -u +%s)" "$(openssl rand -hex 16)" || true)"
KEY_ID="$saved_key"
[ "$code" = "401" ] && pass "unknown key id → 401" \
    || fail "unknown key id → $code, expected 401"

rm -f /tmp/claim-signer-smoke.$$

echo
if [ "$failures" -eq 0 ]; then
    echo "All checks passed."
else
    echo "$failures check(s) failed."
    exit 1
fi
