//! Authenticating the Edge subsystem to the Backend.
//!
//! # What the requirement is
//!
//! Objective O.2, Assurance Level 1, for the **Distributed** implementation
//! class this product uses:
//!
//! > The usage of the Edge subsystem authentication key (API Key) SHALL only be
//! > for the purposes of limiting access to the Backend subsystem.
//! >
//! > Edge and Backend subsystems SHALL be mutually authenticated […]
//! >
//! > For Distributed Implementation Class, the remote claim signing Backend
//! > subsystem of the GP TOE SHALL securely authenticate the calling client,
//! > positively confirming that the calling client is a valid instance of the
//! > Edge subsystem of the GP TOE, before signing a claim […]
//!
//! Symmetric key MAC is one of the methods the requirement names. That is what
//! this implements, over the whole request rather than as a bearer token, so
//! that a captured header cannot be replayed against a different body.
//!
//! ```text
//!   Authorization: C2PA-HMAC-SHA256 key=<id>, ts=<unix>, nonce=<hex>, mac=<base64>
//!
//!   mac = HMAC-SHA256(secret,
//!           method ‖ "\n" ‖ path ‖ "\n" ‖ ts ‖ "\n" ‖ nonce ‖ "\n" ‖ SHA-256(body))
//! ```
//!
//! The other direction — the Edge authenticating the Backend — is TLS. The
//! Edge only ever talks to a URL it was configured with, over TLS 1.3, and the
//! server certificate is what proves the Backend is the Backend. Where the
//! deployment also enables mutual TLS, that is a second, stronger client
//! check layered under this one; see `main.rs`.
//!
//! # Why the client secret is not enough on its own, and why that is fine
//!
//! A browser cannot keep a secret, so an attacker who reads the page can obtain
//! whatever the page holds. That is why the requirement scopes the Edge key to
//! "limiting access to the Backend subsystem" and nothing more: it is a rate
//! and abuse control, not a proof of identity, and the Backend's own key is
//! what the C2PA trust model rests on. In deployment the Edge secret is minted
//! per session by the application server, short-lived, and rate-limited — see
//! `conformance/generator-product-security-architecture.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// How far a request's timestamp may be from the server's clock.
///
/// Two minutes covers ordinary clock drift on a client machine without leaving
/// a captured request useful for long.
const CLOCK_SKEW_SECONDS: i64 = 120;

/// How many nonces to remember. At the skew window above this is far more than
/// any real deployment produces, and it bounds the memory a flood can consume.
const NONCE_CAPACITY: usize = 16_384;

#[derive(Debug, PartialEq, Eq)]
pub enum Denied {
    Missing,
    Malformed(&'static str),
    UnknownKey,
    BadSignature,
    Stale,
    Replayed,
}

impl Denied {
    /// What to tell the caller.
    ///
    /// Deliberately coarse: distinguishing "unknown key" from "bad signature"
    /// to an unauthenticated caller turns the endpoint into an oracle for
    /// enumerating valid key ids. The log records which it was.
    pub fn public_message(&self) -> &'static str {
        match self {
            Denied::Missing => "an Authorization header is required",
            Denied::Malformed(_) => "the Authorization header is malformed",
            Denied::Stale => "the request timestamp is outside the accepted window",
            Denied::Replayed => "this request has already been seen",
            Denied::UnknownKey | Denied::BadSignature => "authentication failed",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Denied::Missing => "no Authorization header".into(),
            Denied::Malformed(what) => format!("malformed Authorization header: {what}"),
            Denied::UnknownKey => "unknown key id".into(),
            Denied::BadSignature => "MAC mismatch".into(),
            Denied::Stale => "timestamp outside the skew window".into(),
            Denied::Replayed => "nonce already used".into(),
        }
    }
}

/// The Edge instances allowed to ask for a signature.
pub struct Clients {
    secrets: HashMap<String, Vec<u8>>,
    seen: Mutex<Nonces>,
}

#[derive(Default)]
struct Nonces {
    /// `(expires_at, key, nonce)`, oldest first.
    entries: std::collections::VecDeque<(i64, String, String)>,
    live: std::collections::HashSet<(String, String)>,
}

impl Clients {
    /// Load client secrets from a JSON object of `{ "<key id>": "<base64>" }`.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let raw: HashMap<String, String> =
            serde_json::from_str(json).map_err(|e| format!("the client secret file: {e}"))?;
        if raw.is_empty() {
            return Err("the client secret file names no clients".into());
        }

        let mut secrets = HashMap::new();
        for (id, encoded) in raw {
            let secret = base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|e| format!("the secret for '{id}' is not Base64: {e}"))?;
            // 32 bytes is the output width of the MAC; a shorter secret adds
            // nothing and a much shorter one is a mistake worth refusing.
            if secret.len() < 32 {
                return Err(format!(
                    "the secret for '{id}' is {} bytes; at least 32 are required",
                    secret.len()
                ));
            }
            secrets.insert(id, secret);
        }

        Ok(Clients {
            secrets,
            seen: Mutex::new(Nonces::default()),
        })
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Authenticate a request, returning the client id it came from.
    pub fn authenticate(
        &self,
        header: Option<&str>,
        method: &str,
        path: &str,
        body: &[u8],
        now: i64,
    ) -> Result<String, Denied> {
        let header = header.ok_or(Denied::Missing)?;
        let credential = Credential::parse(header)?;

        if (now - credential.timestamp).abs() > CLOCK_SKEW_SECONDS {
            return Err(Denied::Stale);
        }

        let secret = self
            .secrets
            .get(&credential.key_id)
            .ok_or(Denied::UnknownKey)?;

        let expected = sign_request(
            secret,
            method,
            path,
            credential.timestamp,
            &credential.nonce,
            body,
        );
        // Constant time: a byte-by-byte comparison here leaks the MAC one byte
        // at a time to anyone willing to measure.
        if expected.ct_eq(&credential.mac).unwrap_u8() != 1 {
            return Err(Denied::BadSignature);
        }

        // Only now, once the MAC is known good, is the nonce recorded. Doing it
        // earlier would let an unauthenticated caller fill the table and evict
        // real entries.
        self.remember(&credential.key_id, &credential.nonce, now)?;
        Ok(credential.key_id)
    }

    fn remember(&self, key_id: &str, nonce: &str, now: i64) -> Result<(), Denied> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Drop anything that can no longer be replayed anyway.
        while let Some((expires, key, value)) = seen.entries.front().cloned() {
            if expires > now && seen.entries.len() < NONCE_CAPACITY {
                break;
            }
            seen.entries.pop_front();
            seen.live.remove(&(key, value));
        }

        let entry = (key_id.to_string(), nonce.to_string());
        if !seen.live.insert(entry.clone()) {
            return Err(Denied::Replayed);
        }
        seen.entries
            .push_back((now + CLOCK_SKEW_SECONDS, entry.0, entry.1));
        Ok(())
    }
}

struct Credential {
    key_id: String,
    timestamp: i64,
    nonce: String,
    mac: Vec<u8>,
}

impl Credential {
    fn parse(header: &str) -> Result<Self, Denied> {
        let rest = header
            .strip_prefix("C2PA-HMAC-SHA256 ")
            .ok_or(Denied::Malformed("unrecognised scheme"))?;

        let mut key_id = None;
        let mut timestamp = None;
        let mut nonce = None;
        let mut mac = None;
        for part in rest.split(',') {
            let (name, value) = part
                .trim()
                .split_once('=')
                .ok_or(Denied::Malformed("expected name=value pairs"))?;
            match name {
                "key" => key_id = Some(value.to_string()),
                "ts" => timestamp = value.parse::<i64>().ok(),
                "nonce" => nonce = Some(value.to_string()),
                "mac" => mac = base64::engine::general_purpose::STANDARD.decode(value).ok(),
                _ => {}
            }
        }

        let credential = Credential {
            key_id: key_id.ok_or(Denied::Malformed("no key id"))?,
            timestamp: timestamp.ok_or(Denied::Malformed("no or unreadable timestamp"))?,
            nonce: nonce.ok_or(Denied::Malformed("no nonce"))?,
            mac: mac.ok_or(Denied::Malformed("no or unreadable MAC"))?,
        };
        // A predictable nonce is no nonce at all, and a 16-byte one is what the
        // client library sends.
        if credential.nonce.len() < 16 {
            return Err(Denied::Malformed("the nonce is too short"));
        }
        if credential.mac.len() != 32 {
            return Err(Denied::Malformed("the MAC is not 32 bytes"));
        }
        Ok(credential)
    }
}

/// The canonical string, MACed. Exposed so the client library and the tests
/// build it the same way this does.
pub fn sign_request(
    secret: &[u8],
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let digest = Sha256::digest(body);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(method.as_bytes());
    mac.update(b"\n");
    mac.update(path.as_bytes());
    mac.update(b"\n");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(&hex(&digest));
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    out
}

/// Seconds since the epoch, for the skew check.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [3u8; 32];

    fn clients() -> Clients {
        let encoded = base64::engine::general_purpose::STANDARD.encode(SECRET);
        Clients::from_json(&format!("{{\"edge-1\":\"{encoded}\"}}")).unwrap()
    }

    fn header(nonce: &str, timestamp: i64, body: &[u8], secret: &[u8]) -> String {
        let mac = sign_request(secret, "POST", "/v1/sign", timestamp, nonce, body);
        format!(
            "C2PA-HMAC-SHA256 key=edge-1, ts={timestamp}, nonce={nonce}, mac={}",
            base64::engine::general_purpose::STANDARD.encode(mac)
        )
    }

    #[test]
    fn a_correctly_signed_request_is_accepted() {
        let clients = clients();
        let body = br#"{"toBeSigned":"AAAA"}"#;
        let header = header("0123456789abcdef", 1_800_000_000, body, &SECRET);
        assert_eq!(
            clients
                .authenticate(Some(&header), "POST", "/v1/sign", body, 1_800_000_000)
                .unwrap(),
            "edge-1"
        );
    }

    #[test]
    fn a_changed_body_invalidates_the_mac() {
        // The point of MACing the body rather than issuing a bearer token: a
        // captured header cannot be pointed at a different claim.
        let clients = clients();
        let header = header("0123456789abcdef", 1_800_000_000, b"one", &SECRET);
        assert_eq!(
            clients.authenticate(Some(&header), "POST", "/v1/sign", b"two", 1_800_000_000),
            Err(Denied::BadSignature)
        );
    }

    #[test]
    fn a_changed_path_or_method_invalidates_the_mac() {
        let clients = clients();
        let body = b"x";
        let header = header("0123456789abcdef", 1_800_000_000, body, &SECRET);
        assert_eq!(
            clients.authenticate(Some(&header), "POST", "/v1/identity", body, 1_800_000_000),
            Err(Denied::BadSignature)
        );
        assert_eq!(
            clients.authenticate(Some(&header), "GET", "/v1/sign", body, 1_800_000_000),
            Err(Denied::BadSignature)
        );
    }

    #[test]
    fn a_replayed_request_is_refused() {
        let clients = clients();
        let body = b"x";
        let header = header("0123456789abcdef", 1_800_000_000, body, &SECRET);
        assert!(clients
            .authenticate(Some(&header), "POST", "/v1/sign", body, 1_800_000_000)
            .is_ok());
        assert_eq!(
            clients.authenticate(Some(&header), "POST", "/v1/sign", body, 1_800_000_000),
            Err(Denied::Replayed)
        );
    }

    #[test]
    fn a_stale_request_is_refused_before_the_secret_is_consulted() {
        let clients = clients();
        let body = b"x";
        let header = header("0123456789abcdef", 1_800_000_000, body, &SECRET);
        assert_eq!(
            clients.authenticate(Some(&header), "POST", "/v1/sign", body, 1_800_000_600),
            Err(Denied::Stale)
        );
        // And a request from the future, which is the same problem mirrored.
        assert_eq!(
            clients.authenticate(Some(&header), "POST", "/v1/sign", body, 1_799_999_400),
            Err(Denied::Stale)
        );
    }

    #[test]
    fn a_failed_request_does_not_consume_its_nonce() {
        // Otherwise anyone could burn a nonce they had observed, and the real
        // request behind it would be rejected as a replay.
        let clients = clients();
        let body = b"x";
        let forged = header("0123456789abcdef", 1_800_000_000, body, &[9u8; 32]);
        assert_eq!(
            clients.authenticate(Some(&forged), "POST", "/v1/sign", body, 1_800_000_000),
            Err(Denied::BadSignature)
        );

        let genuine = header("0123456789abcdef", 1_800_000_000, body, &SECRET);
        assert!(clients
            .authenticate(Some(&genuine), "POST", "/v1/sign", body, 1_800_000_000)
            .is_ok());
    }

    #[test]
    fn an_unknown_key_and_a_bad_mac_look_the_same_from_outside() {
        // The endpoint must not become a way to enumerate valid key ids.
        assert_eq!(
            Denied::UnknownKey.public_message(),
            Denied::BadSignature.public_message()
        );
        // But the log distinguishes them.
        assert_ne!(Denied::UnknownKey.detail(), Denied::BadSignature.detail());
    }

    #[test]
    fn malformed_headers_are_rejected_rather_than_parsed_loosely() {
        let clients = clients();
        for header in [
            "Bearer abc",
            "C2PA-HMAC-SHA256 ",
            "C2PA-HMAC-SHA256 key=edge-1",
            "C2PA-HMAC-SHA256 key=edge-1, ts=notanumber, nonce=0123456789abcdef, mac=AAAA",
            "C2PA-HMAC-SHA256 key=edge-1, ts=1800000000, nonce=short, mac=AAAA",
        ] {
            assert!(
                matches!(
                    clients.authenticate(Some(header), "POST", "/v1/sign", b"x", 1_800_000_000),
                    Err(Denied::Malformed(_))
                ),
                "{header:?} should not parse"
            );
        }
        assert_eq!(
            clients.authenticate(None, "POST", "/v1/sign", b"x", 1_800_000_000),
            Err(Denied::Missing)
        );
    }

    #[test]
    fn a_short_client_secret_is_refused_at_load_time() {
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        // `unwrap_err` would need `Clients: Debug`, and deriving that on a
        // type holding client secrets is exactly how secrets end up in logs.
        let Err(error) = Clients::from_json(&format!("{{\"edge-1\":\"{short}\"}}")) else {
            panic!("a short secret should be refused");
        };
        assert!(error.contains("at least 32"), "{error}");
    }

    #[test]
    fn an_empty_client_list_is_refused() {
        assert!(Clients::from_json("{}").is_err());
    }
}
