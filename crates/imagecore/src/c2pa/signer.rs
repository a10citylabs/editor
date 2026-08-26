//! The signing credentials this build carries.
//!
//! The PEM comes from `build.rs`, which reads the `C2PA_SIGNING_CERT` and
//! `C2PA_SIGNING_KEY` environment variables when both are set and falls back to
//! the demo files in `signing/` otherwise.
//!
//! **This key is public and cannot be otherwise.** The engine is compiled to
//! WebAssembly and served to browsers, so whatever key it holds is downloadable
//! by anyone who loads the page. That is a property of signing on the client,
//! not a corner cut here: there is no way to give a browser the ability to sign
//! without also giving it the means. `signing/README.md` works through what
//! GitHub Actions secrets do and do not change about that, and sketches the two
//! designs (remote signing, per-user certificates) that produce credentials
//! anyone should actually trust.
//!
//! What still holds with a public key is worth being precise about, because it
//! is not nothing: the hard binding proves the pixels have not changed since
//! signing, and the actions describe what the editor did. What does not hold is
//! *identity* — anybody can produce a manifest bearing this signer's name. The
//! UI says so on every credential it writes.

use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

include!(concat!(env!("OUT_DIR"), "/signing_credentials.rs"));

/// A loaded key with the certificate chain that goes in `x5chain`.
pub struct Credentials {
    pub key: SigningKey,
    /// DER certificates, end-entity first. The trust anchor is not included,
    /// per C2PA 2.2 section 13.2.2.
    pub chain: Vec<Vec<u8>>,
}

/// Parse the compiled-in credentials.
pub fn load() -> Result<Credentials, String> {
    let key = SigningKey::from_pkcs8_pem(SIGNING_KEY_PEM)
        .map_err(|e| format!("the signing key is not a usable PKCS#8 P-256 key: {e}"))?;

    let chain = super::x509::pem_to_der(SIGNING_CERT_CHAIN_PEM)
        .map_err(|e| format!("the signing certificate chain could not be read: {e}"))?;

    // A chain whose leaf does not match the key would produce signatures that
    // fail against the certificate shipped beside them. Catching it here turns
    // a confusing downstream validation failure into a build-time-obvious one.
    let leaf = chain
        .first()
        .ok_or_else(|| "the certificate chain is empty".to_string())?;
    let certificate =
        super::x509::parse_certificate(leaf).map_err(|e| format!("signing certificate: {e}"))?;
    let expected = key.verifying_key().to_encoded_point(false);
    if certificate.public_key != expected.as_bytes() {
        return Err("the signing key does not match its certificate".into());
    }

    Ok(Credentials { key, chain })
}

/// How this build's signer describes itself, for the UI.
pub fn describe() -> Result<SignerDescription, String> {
    let chain = super::x509::pem_to_der(SIGNING_CERT_CHAIN_PEM)
        .map_err(|e| format!("the signing certificate chain could not be read: {e}"))?;
    let leaf = super::x509::parse_certificate(&chain[0]).map_err(|e| e.to_string())?;

    // The anchor is optional: a build supplying its own chain through the
    // environment need not include one.
    let root = super::x509::pem_to_der(SIGNING_ROOT_CA_PEM)
        .ok()
        .and_then(|der| {
            der.first()
                .and_then(|d| super::x509::parse_certificate(d).ok())
        });

    Ok(SignerDescription {
        common_name: leaf.subject_common_name,
        organisation: leaf.subject_organisation,
        issuer: if leaf.issuer_common_name.is_empty() {
            leaf.issuer
        } else {
            leaf.issuer_common_name
        },
        not_after: leaf.not_after,
        extended_key_usage: leaf.extended_key_usage,
        anchor_is_self_signed: root.map(|r| r.issuer == r.subject).unwrap_or(false),
        credential_source: SIGNING_CREDENTIAL_SOURCE,
    })
}

pub struct SignerDescription {
    pub common_name: String,
    pub organisation: String,
    pub issuer: String,
    pub not_after: String,
    pub extended_key_usage: Vec<String>,
    /// True when the chain terminates in a self-signed root, which is the
    /// giveaway that no public CA is involved.
    pub anchor_is_self_signed: bool,
    /// `"repository"` or `"environment"`, per `build.rs`.
    pub credential_source: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_credentials_load() {
        let credentials = load().expect("build.rs should have supplied working credentials");
        assert!(!credentials.chain.is_empty());
    }

    #[test]
    fn the_key_matches_its_certificate() {
        // `load` enforces this; the test is here so the failure names the cause
        // if someone regenerates one file without the other.
        let credentials = load().unwrap();
        let certificate = super::super::x509::parse_certificate(&credentials.chain[0]).unwrap();
        assert_eq!(
            certificate.public_key,
            credentials
                .key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        );
    }

    #[test]
    fn the_chain_omits_the_trust_anchor() {
        // Section 13.2.2: x5chain carries the signer and intermediates, never
        // the root. With a two-deep chain that means exactly one certificate.
        let credentials = load().unwrap();
        assert_eq!(credentials.chain.len(), 1);

        let leaf = super::super::x509::parse_certificate(&credentials.chain[0]).unwrap();
        assert!(!leaf.is_ca, "the end-entity certificate must not be a CA");
    }

    #[test]
    fn describe_reports_an_untrusted_self_signed_anchor() {
        let described = describe().unwrap();
        assert!(!described.common_name.is_empty());
        assert!(
            described.anchor_is_self_signed,
            "the demo anchor is self-signed, and the UI depends on knowing that"
        );
        assert_eq!(described.credential_source, "repository");
    }
}
