//! The RFC 3161 client: asking a time-stamping authority to stamp a signature.
//!
//! # Why the Backend does this and the Edge cannot
//!
//! Two reasons, and the second is the interesting one.
//!
//! The obvious one is reach: a time-stamping authority is an HTTP endpoint with
//! its own TLS, and the browser tab would need it to serve permissive CORS
//! headers, which authorities do not.
//!
//! The real one is that a C2PA v2 time-stamp covers the *signature*, not the
//! claim (section 10.3.2.5.2). The signature does not exist until the Backend
//! has made it. So the stamp has to be fetched between signing and answering,
//! in the same request, which is exactly where this sits.
//!
//! # What is sent
//!
//! A `TimeStampReq` carrying only a SHA-256 digest of the signature. Nothing
//! about the image, the claim, or the person reaches the authority — the same
//! property that holds between the browser and this service holds between this
//! service and the TSA.
//!
//! ```text
//!   TimeStampReq ::= SEQUENCE {
//!     version            INTEGER { v1(1) },
//!     messageImprint     MessageImprint,
//!     nonce              INTEGER OPTIONAL,
//!     certReq            BOOLEAN DEFAULT FALSE  -- asserted: the token has to
//!   }                                              carry the TSA certificate
//!                                                  or no validator can check it
//! ```

use imagecore::c2pa::{der, timestamp};
use rand::Rng;
use sha2::{Digest, Sha256};

const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const CONTENT_TYPE: &str = "application/timestamp-query";
const RESPONSE_TYPE: &str = "application/timestamp-reply";

/// A configured time-stamping authority.
pub struct Tsa {
    url: String,
    timeout: std::time::Duration,
}

impl Tsa {
    pub fn new(url: impl Into<String>, timeout: std::time::Duration) -> Self {
        Tsa {
            url: url.into(),
            timeout,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Ask for a token over `signature`, returning the DER `TimeStampToken`.
    ///
    /// Blocking, and called from a blocking task: the request is a single small
    /// round trip and an async HTTP stack for it would be more moving parts
    /// than the job needs.
    pub fn stamp(&self, signature: &[u8]) -> Result<Vec<u8>, String> {
        let nonce: u64 = rand::thread_rng().gen();
        let request = build_request(signature, nonce);

        let agent = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .user_agent(concat!("a10city-claim-signer/", env!("CARGO_PKG_VERSION")))
            .build();

        let response = agent
            .post(&self.url)
            .set("Content-Type", CONTENT_TYPE)
            .send_bytes(&request)
            .map_err(|e| format!("the time-stamping authority could not be reached: {e}"))?;

        // Some authorities answer with the generic octet-stream type; refusing
        // those would be pedantry. A HTML error page, though, is worth naming
        // rather than letting the DER parser produce something cryptic.
        let content_type = response.content_type().to_string();
        if content_type.contains("html") || content_type.contains("json") {
            return Err(format!(
                "the time-stamping authority answered with {content_type}, not {RESPONSE_TYPE}"
            ));
        }

        let mut body = Vec::new();
        response
            .into_reader()
            .take(1024 * 1024)
            .read_to_end(&mut body)
            .map_err(|e| format!("reading the time-stamp response: {e}"))?;

        let token = timestamp::token_from_response(&body)?;

        // Check the token before it is handed on. A stamp over the wrong bytes
        // would be embedded, shipped, and only noticed by someone else's
        // validator; catching it here turns that into a log line.
        let parsed = timestamp::parse(&token)
            .map_err(|e| format!("the time-stamp token did not parse: {e}"))?;
        let expected = Sha256::digest(signature);
        if parsed.imprint != expected[..] {
            return Err("the time-stamp covers something other than the signature sent".into());
        }
        if parsed.certificates.is_empty() {
            return Err(
                "the time-stamp carries no certificates, so no validator could check it".into(),
            );
        }

        Ok(token)
    }
}

use std::io::Read as _;

/// Build the DER `TimeStampReq`.
fn build_request(signature: &[u8], nonce: u64) -> Vec<u8> {
    let digest = Sha256::digest(signature);
    der::sequence(&[
        der::integer(1),
        der::sequence(&[
            der::algorithm_with_null(OID_SHA256),
            der::octet_string(&digest),
        ]),
        der::integer(nonce),
        // certReq: without it most authorities omit their certificate, and a
        // token whose signer cannot be found fails section 15.8.2.
        der::boolean(true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use imagecore::c2pa::x509;

    #[test]
    fn the_request_carries_only_a_digest() {
        // The privacy property, asserted rather than described: the authority
        // learns 32 bytes and a nonce.
        let signature = vec![0xAB; 64];
        let request = build_request(&signature, 42);
        assert!(
            !request
                .windows(signature.len())
                .any(|w| w == signature.as_slice()),
            "the signature itself must not be sent"
        );
        assert!(
            request.len() < 128,
            "the request is {} bytes",
            request.len()
        );
    }

    #[test]
    fn the_request_is_well_formed_der() {
        let request = build_request(&[1, 2, 3], 7);
        let sequence = x509::read_tlv(&request).unwrap();
        assert_eq!(sequence.tag, 0x30);
        assert_eq!(sequence.total, request.len());

        let fields = x509::children(sequence.value).unwrap();
        assert_eq!(fields.len(), 4, "version, imprint, nonce, certReq");
        assert_eq!(fields[0].tag, 0x02);
        assert_eq!(fields[0].value, [1]);
        assert_eq!(fields[3].tag, 0x01);
        assert_eq!(fields[3].value, [0xFF], "certReq must be asserted");
    }

    #[test]
    fn the_imprint_is_the_sha256_of_the_signature() {
        let signature = b"a signature";
        let request = build_request(signature, 1);
        let fields = x509::children(x509::read_tlv(&request).unwrap().value).unwrap();
        let imprint = x509::children(fields[1].value).unwrap();
        assert_eq!(imprint[1].value, &Sha256::digest(signature)[..]);
    }

    #[test]
    fn each_request_carries_a_fresh_nonce() {
        // A fixed nonce would let a replayed response pass for a new stamp.
        let one = build_request(b"x", rand::random());
        let two = build_request(b"x", rand::random());
        assert_ne!(one, two);
    }
}
