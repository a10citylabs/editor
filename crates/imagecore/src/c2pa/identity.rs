//! The signing identity the Edge subsystem is given, and never holds.
//!
//! # What changed, and why it had to
//!
//! An earlier version of this engine compiled a private key into the
//! WebAssembly module. That is disqualifying under the C2PA Conformance
//! Program: objective O.2 of the Generator Product Security Requirements says
//! the Target of Evaluation shall keep the claim signing key encrypted at rest
//! *and* in volatile memory except while signing, shall restrict access to it
//! by least privilege, and shall be able to rotate it. A key served to every
//! visitor as part of a static bundle fails all three, and no amount of
//! obfuscation changes that — so a browser-only claim generator cannot reach
//! even Assurance Level 1.
//!
//! The fix is architectural rather than cosmetic. The product is now a
//! **Distributed** implementation: the browser (the Edge subsystem) builds the
//! asset, the assertions and the claim, and `services/claim-signer` (the
//! Backend subsystem) holds the key and returns a signature over the 32-byte
//! digest structure the Edge sends it. The image still never leaves the tab.
//!
//! What this module holds is the *public* half of that arrangement: the
//! certificate chain, the algorithm, and how much room to reserve for a
//! time-stamp. All of it is public information that the Backend publishes, and
//! all of it is needed on the Edge before signing, because the size of the
//! finished signature box — which the hard binding commits to — depends on it.

use super::x509;

/// COSE algorithm identifiers, as C2PA 2.2 section 13.2.1 allows them.
pub mod alg {
    pub const ES256: i64 = -7;
    pub const ES384: i64 = -35;
    pub const ES512: i64 = -36;
    pub const PS256: i64 = -37;
    pub const PS384: i64 = -38;
    pub const PS512: i64 = -39;
    pub const ED25519: i64 = -8;

    /// How many bytes a signature in this algorithm occupies.
    ///
    /// The manifest builder reserves space for the signature before it exists,
    /// so a wrong answer here is a wrong byte offset in the hard binding. For
    /// ECDSA the answer is fixed by the curve; for RSA it is the modulus size,
    /// which the caller has to read off the certificate.
    pub fn signature_len(algorithm: i64, rsa_modulus_bytes: Option<usize>) -> Option<usize> {
        match algorithm {
            ES256 => Some(64),
            ES384 => Some(96),
            ES512 => Some(132),
            ED25519 => Some(64),
            PS256 | PS384 | PS512 => rsa_modulus_bytes,
            _ => None,
        }
    }

    pub fn name(algorithm: i64) -> &'static str {
        match algorithm {
            ES256 => "ES256",
            ES384 => "ES384",
            ES512 => "ES512",
            PS256 => "PS256",
            PS384 => "PS384",
            PS512 => "PS512",
            ED25519 => "Ed25519",
            _ => "Unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<i64> {
        Some(match name {
            "ES256" => ES256,
            "ES384" => ES384,
            "ES512" => ES512,
            "PS256" => PS256,
            "PS384" => PS384,
            "PS512" => PS512,
            "Ed25519" | "EdDSA" => ED25519,
            _ => return None,
        })
    }
}

/// What the Backend published about the credential it will sign with.
///
/// Everything here is public. The Edge caches it for the session and uses it to
/// size the signature box; it is re-fetched when the Backend reports a
/// different `key_id`, which is how key rotation reaches the browser without a
/// redeploy.
#[derive(Clone, Debug)]
pub struct SigningIdentity {
    /// DER certificates for `x5chain`, end-entity first, trust anchor omitted
    /// (C2PA 2.2 section 13.2.2).
    pub chain: Vec<Vec<u8>>,
    /// COSE algorithm identifier the Backend signs with.
    pub algorithm: i64,
    /// Which key version this chain belongs to, so the Edge can notice a
    /// rotation mid-session and re-fetch rather than sign against a stale
    /// certificate.
    pub key_id: String,
    /// Bytes to reserve in the COSE unprotected header for an RFC 3161
    /// time-stamp token. Zero means the Backend has no time-stamping
    /// authority configured and the signature will carry none.
    pub timestamp_budget: usize,
}

impl SigningIdentity {
    /// Build an identity from a PEM chain, checking the parts the Edge depends
    /// on rather than trusting the Backend's word for them.
    ///
    /// The Backend is inside the Target of Evaluation, so this is not a trust
    /// boundary in the security sense. It is still worth checking: a chain that
    /// does not parse here produces a manifest whose offsets are wrong, and the
    /// failure would otherwise surface as an unverifiable image rather than as
    /// a setup error.
    pub fn from_pem(
        pem: &str,
        algorithm: i64,
        key_id: impl Into<String>,
        timestamp_budget: usize,
    ) -> Result<Self, String> {
        let chain = x509::pem_to_der(pem)
            .map_err(|e| format!("the signing certificate chain could not be read: {e}"))?;
        Self::new(chain, algorithm, key_id, timestamp_budget)
    }

    pub fn new(
        chain: Vec<Vec<u8>>,
        algorithm: i64,
        key_id: impl Into<String>,
        timestamp_budget: usize,
    ) -> Result<Self, String> {
        let leaf = chain
            .first()
            .ok_or_else(|| "the signing certificate chain is empty".to_string())?;
        let certificate =
            x509::parse_certificate(leaf).map_err(|e| format!("signing certificate: {e}"))?;

        if certificate.is_ca {
            return Err("the end-entity certificate must not be a CA".into());
        }
        if alg::signature_len(algorithm, certificate.rsa_modulus_bytes()).is_none() {
            return Err(format!(
                "the signature algorithm {} is not one this build can size",
                alg::name(algorithm)
            ));
        }

        Ok(SigningIdentity {
            chain,
            algorithm,
            key_id: key_id.into(),
            timestamp_budget,
        })
    }

    /// Size of the signature the Backend will return.
    pub fn signature_len(&self) -> usize {
        let modulus = x509::parse_certificate(&self.chain[0])
            .ok()
            .and_then(|c| c.rsa_modulus_bytes());
        alg::signature_len(self.algorithm, modulus).unwrap_or(0)
    }

    /// The leaf certificate, parsed.
    pub fn leaf(&self) -> Result<x509::Certificate, String> {
        x509::parse_certificate(&self.chain[0]).map_err(|e| e.to_string())
    }

    /// How this signer describes itself, for the interface.
    pub fn describe(&self) -> Result<SignerDescription, String> {
        let leaf = self.leaf()?;
        Ok(SignerDescription {
            common_name: leaf.subject_common_name.clone(),
            organisation: leaf.subject_organisation.clone(),
            issuer: if leaf.issuer_common_name.is_empty() {
                leaf.issuer.clone()
            } else {
                leaf.issuer_common_name.clone()
            },
            not_before: leaf.not_before.clone(),
            not_after: leaf.not_after.clone(),
            algorithm: alg::name(self.algorithm).to_string(),
            assurance_level: leaf.c2pa_assurance_level,
            cpl_record_id: leaf.c2pa_cpl_record_id.clone(),
            claim_signing_eku: leaf.has_claim_signing_eku(),
            time_stamped: self.timestamp_budget > 0,
            key_id: self.key_id.clone(),
        })
    }
}

/// The signer, as the interface presents it to a person.
///
/// `assurance_level` and `cpl_record_id` come straight out of the certificate.
/// They are the two facts that separate a conformant Generator Product from
/// something that merely produces well-formed CBOR, and showing them beats any
/// wording the app could invent for itself.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerDescription {
    pub common_name: String,
    pub organisation: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub algorithm: String,
    /// 1 or 2 from the `c2pa-al` extension; `None` when the certificate carries
    /// none, which means it was not issued under the C2PA Certificate Policy.
    pub assurance_level: Option<u32>,
    /// The Conforming Products List record this instance signs under.
    pub cpl_record_id: Option<String>,
    /// Whether the leaf asserts `c2pa-kp-claimSigning` (1.3.6.1.4.1.62558.2.1).
    pub claim_signing_eku: bool,
    pub time_stamped: bool,
    pub key_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa::testpki;

    #[test]
    fn the_test_chain_loads_as_an_identity() {
        let identity = testpki::identity();
        assert_eq!(identity.algorithm, alg::ES256);
        assert_eq!(identity.signature_len(), 64);
        // Leaf plus issuing CA, and never the root.
        assert_eq!(identity.chain.len(), 2);
    }

    #[test]
    fn the_identity_reports_the_conformance_facts_from_the_certificate() {
        let described = testpki::identity().describe().unwrap();
        assert_eq!(described.assurance_level, Some(1));
        assert!(
            described.claim_signing_eku,
            "the leaf must assert c2pa-kp-claimSigning"
        );
        assert_eq!(
            described.cpl_record_id.as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(described.algorithm, "ES256");
    }

    #[test]
    fn a_ca_certificate_is_refused_as_an_end_entity() {
        let chain = vec![testpki::issuing_ca_der()];
        let error = SigningIdentity::new(chain, alg::ES256, "k1", 0).unwrap_err();
        assert!(error.contains("must not be a CA"), "{error}");
    }

    #[test]
    fn an_unsizable_algorithm_is_refused_rather_than_guessed() {
        // Reserving the wrong number of bytes would corrupt the hard binding's
        // offsets, so an algorithm this build cannot size has to be a setup
        // error rather than a silent default.
        let chain = vec![testpki::leaf_der()];
        let error = SigningIdentity::new(chain, -99, "k1", 0).unwrap_err();
        assert!(error.contains("not one this build can size"), "{error}");
    }
}
