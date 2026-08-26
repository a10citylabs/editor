//! Where the claim signing key lives, and how briefly it exists in the clear.
//!
//! # What objective O.2 actually asks for
//!
//! The C2PA Generator Product Security Requirements, Assurance Level 1:
//!
//! > Where persistent storage is required, the GP TOE SHALL store the claim
//! > signing key in encrypted form, using industry best practices for
//! > encryption algorithms and key lengths. The GP TOE SHALL keep the claim
//! > signing key encrypted when present in volatile memory, except when the key
//! > is being prepared for use in signing claims […]
//! >
//! > GP TOE SHALL control access to the signing key in decrypted form,
//! > following the principle of least privilege […]
//! >
//! > GP TOE SHALL be capable of rotating the claim signing key.
//!
//! Three requirements, and this module is the answer to all three:
//!
//! - **Encrypted at rest.** AES-256-GCM, with a key-encryption key that comes
//!   from outside the file system the ciphertext lives on. In the reference
//!   deployment that is a cloud KMS; in development it is an environment
//!   variable, and the service says which it used at startup so nobody
//!   discovers the difference in production.
//! - **Encrypted in memory except while signing.** [`Keystore`] holds only the
//!   ciphertext. The plaintext exists inside [`Keystore::sign`] and nowhere
//!   else, in a buffer that zeroes itself on the way out. There is no accessor
//!   that hands the key to a caller, because a key you cannot get hold of
//!   cannot be leaked by the next person to add a feature.
//! - **Rotatable.** Versions are directories; one symlink-free `active` file
//!   names the current one. `claim-signer import` and `claim-signer activate`
//!   do the rotation, and old versions stay readable so that images signed
//!   under them keep validating.
//!
//! # Layout
//!
//! ```text
//!   keystore/
//!     active                     the id of the version to sign with
//!     2026-08-signer-1/
//!       key.enc                  nonce ‖ AES-256-GCM(private key, PKCS#8 DER)
//!       chain.pem                x5chain: leaf first, trust anchor omitted
//!       meta.json                { "algorithm": "ES256", "importedAt": … }
//! ```

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use imagecore::c2pa::x509;
use rand::RngCore;
use zeroize::Zeroizing;

/// Additional authenticated data, so a `key.enc` cannot be moved between
/// versions or between deployments without the decryption failing.
const AAD_PREFIX: &[u8] = b"a10city/claim-signer/key/v1/";
const NONCE_LEN: usize = 12;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Something about the deployment is wrong: a missing file, an unreadable
    /// key, a key-encryption key of the wrong length.
    Configuration(String),
    /// The ciphertext did not authenticate. Either the key-encryption key is
    /// wrong or the stored key has been tampered with; both are fatal and
    /// neither should be distinguished to a caller.
    Unusable(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Configuration(m) => write!(f, "{m}"),
            Error::Unusable(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

fn config<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Configuration(message.into()))
}

/// A 32-byte key-encryption key, held only as long as the process runs.
///
/// Wrapped rather than passed as a `[u8; 32]` so that it zeroes on drop and so
/// that its provenance travels with it — the startup banner reports whether the
/// deployment is using a KMS or an environment variable, and that reporting is
/// only honest if the answer is recorded where the key is.
pub struct KeyEncryptionKey {
    material: Zeroizing<[u8; 32]>,
    pub source: &'static str,
}

impl KeyEncryptionKey {
    /// Read the key-encryption key from the environment.
    ///
    /// `CLAIM_SIGNER_KEK_FILE` wins over `CLAIM_SIGNER_KEK`: a file can be a
    /// mounted secret with its own access control, where an environment
    /// variable is visible to anything that can read `/proc`. Both take
    /// standard Base64 of exactly 32 bytes.
    pub fn from_environment() -> Result<Self> {
        let (encoded, source) = match (
            std::env::var("CLAIM_SIGNER_KEK_FILE").ok(),
            std::env::var("CLAIM_SIGNER_KEK").ok(),
        ) {
            (Some(path), _) => {
                let contents = std::fs::read_to_string(&path)
                    .map_err(|e| Error::Configuration(format!("reading {path}: {e}")))?;
                (contents.trim().to_string(), "file")
            }
            (None, Some(value)) => (value.trim().to_string(), "environment"),
            (None, None) => {
                return config(
                    "no key-encryption key: set CLAIM_SIGNER_KEK_FILE (preferred) or \
                     CLAIM_SIGNER_KEK to 32 Base64-encoded bytes",
                )
            }
        };

        Self::from_base64(&encoded, source)
    }

    pub fn from_base64(encoded: &str, source: &'static str) -> Result<Self> {
        use base64::Engine as _;
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(encoded.trim())
                .map_err(|e| {
                    Error::Configuration(format!("the key-encryption key is not Base64: {e}"))
                })?,
        );
        if decoded.len() != 32 {
            return config(format!(
                "the key-encryption key must be 32 bytes, not {}",
                decoded.len()
            ));
        }
        let mut material = Zeroizing::new([0u8; 32]);
        material.copy_from_slice(&decoded);
        Ok(KeyEncryptionKey { material, source })
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(self.material.as_slice().into())
    }
}

/// One version of the signing credential.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionMeta {
    /// COSE algorithm name, e.g. `ES256`.
    pub algorithm: String,
    /// When this version was imported, RFC 3339.
    pub imported_at: String,
    /// Free text: which CA issued it, which order it came from.
    #[serde(default)]
    pub note: String,
}

/// The signing credential, with the private half still encrypted.
pub struct Version {
    pub id: String,
    pub meta: VersionMeta,
    /// PEM chain, leaf first. Public, and served to the Edge.
    pub chain_pem: String,
    /// The leaf, parsed, so the service can report the Assurance Level and
    /// notice an expiring certificate before a validator does.
    pub leaf: x509::Certificate,
    /// `nonce ‖ ciphertext ‖ tag`, exactly as stored.
    sealed: Vec<u8>,
}

/// The signing credentials on disk, and the operations allowed on them.
pub struct Keystore {
    kek: KeyEncryptionKey,
    active: Version,
}

impl Keystore {
    /// Open a keystore and load the active version.
    pub fn open(root: impl AsRef<Path>, kek: KeyEncryptionKey) -> Result<Self> {
        let root = root.as_ref();
        let id = active_id(root)?;
        let active = load_version(root, &id)?;

        // Prove the key decrypts and matches its certificate now, at startup,
        // rather than on the first signing request. A deployment with a
        // mismatched key should refuse to come up, not fail one user's save.
        let store = Keystore { kek, active };
        store.verify_active()?;
        Ok(store)
    }

    pub fn active(&self) -> &Version {
        &self.active
    }

    pub fn kek_source(&self) -> &'static str {
        self.kek.source
    }

    /// Sign `message` with the active key.
    ///
    /// The plaintext key exists only inside this function. It is decrypted,
    /// used, and zeroed before returning — `Zeroizing` for the DER, and the
    /// `p256`/`p384` key types zero their own scalars on drop.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let der = self.unseal()?;
        match self.active.meta.algorithm.as_str() {
            "ES256" => {
                use p256::ecdsa::signature::Signer;
                use p256::pkcs8::DecodePrivateKey;
                let key = p256::ecdsa::SigningKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Unusable(format!("the stored key is not P-256: {e}")))?;
                let signature: p256::ecdsa::Signature = key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            "ES384" => {
                use p384::ecdsa::signature::Signer;
                use p384::pkcs8::DecodePrivateKey;
                let key = p384::ecdsa::SigningKey::from_pkcs8_der(&der)
                    .map_err(|e| Error::Unusable(format!("the stored key is not P-384: {e}")))?;
                let signature: p384::ecdsa::Signature = key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            other => config(format!(
                "{other} is not a signature algorithm this build can sign with"
            )),
        }
    }

    /// Decrypt the active key. Private on purpose: see the module docs.
    fn unseal(&self) -> Result<Zeroizing<Vec<u8>>> {
        let sealed = &self.active.sealed;
        if sealed.len() <= NONCE_LEN {
            return Err(Error::Unusable("the stored key is truncated".into()));
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let aad = aad_for(&self.active.id);
        self.kek
            .cipher()
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                Error::Unusable(
                    "the stored key did not decrypt: the key-encryption key is wrong, or the \
                     keystore has been altered"
                        .into(),
                )
            })
    }

    /// Check the active key matches the certificate beside it.
    ///
    /// A mismatch produces signatures that fail against the very certificate
    /// shipped with them, and the failure would otherwise surface in someone
    /// else's validator days later.
    fn verify_active(&self) -> Result<()> {
        let probe = b"claim-signer startup self-check";
        let signature = self.sign(probe)?;
        let algorithm = match self.active.meta.algorithm.as_str() {
            "ES256" => imagecore::c2pa::identity::alg::ES256,
            "ES384" => imagecore::c2pa::identity::alg::ES384,
            other => return config(format!("unsupported algorithm {other}")),
        };
        imagecore::c2pa::verify::by_cose_algorithm(algorithm, &self.active.leaf, probe, &signature)
            .map_err(|e| {
                Error::Configuration(format!(
                    "the active signing key does not match the certificate beside it: {e}"
                ))
            })
    }

    /// Import a new version. This is half of key rotation; [`Keystore::activate`]
    /// is the other half, kept separate so a new credential can be staged and
    /// checked before anything starts signing with it.
    pub fn import(
        root: impl AsRef<Path>,
        kek: &KeyEncryptionKey,
        id: &str,
        key_pem: &str,
        chain_pem: &str,
        meta: VersionMeta,
    ) -> Result<()> {
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return config("a version id may only hold letters, digits, '-' and '_'");
        }
        let directory = root.as_ref().join(id);
        if directory.exists() {
            return config(format!("version {id} already exists"));
        }

        let der = private_key_der(key_pem)?;
        let chain = x509::pem_to_der(chain_pem)
            .map_err(|e| Error::Configuration(format!("the certificate chain: {e}")))?;
        let leaf = chain
            .first()
            .ok_or_else(|| Error::Configuration("the certificate chain is empty".into()))
            .and_then(|der| {
                x509::parse_certificate(der)
                    .map_err(|e| Error::Configuration(format!("the leaf certificate: {e}")))
            })?;
        if leaf.is_ca {
            return config("the end-entity certificate must not be a CA");
        }

        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = aad_for(id);
        let sealed = kek
            .cipher()
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &der,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Unusable("could not encrypt the key".into()))?;

        std::fs::create_dir_all(&directory)
            .map_err(|e| Error::Configuration(format!("creating {}: {e}", directory.display())))?;
        let mut on_disk = nonce.to_vec();
        on_disk.extend_from_slice(&sealed);
        write_private(&directory.join("key.enc"), &on_disk)?;
        write_file(&directory.join("chain.pem"), chain_pem.as_bytes())?;
        write_file(
            &directory.join("meta.json"),
            serde_json::to_string_pretty(&meta)
                .map_err(|e| Error::Configuration(e.to_string()))?
                .as_bytes(),
        )?;

        Ok(())
    }

    /// Point `active` at an existing version.
    pub fn activate(root: impl AsRef<Path>, id: &str) -> Result<()> {
        let root = root.as_ref();
        if !root.join(id).join("key.enc").exists() {
            return config(format!("version {id} is not in the keystore"));
        }
        write_file(&root.join("active"), id.as_bytes())
    }

    /// Every version present, newest first by id.
    pub fn versions(root: impl AsRef<Path>) -> Result<Vec<String>> {
        let root = root.as_ref();
        let mut ids: Vec<String> = std::fs::read_dir(root)
            .map_err(|e| Error::Configuration(format!("reading {}: {e}", root.display())))?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.path().join("key.enc").exists())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        ids.sort();
        ids.reverse();
        Ok(ids)
    }
}

fn aad_for(id: &str) -> Vec<u8> {
    let mut aad = AAD_PREFIX.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

fn active_id(root: &Path) -> Result<String> {
    let path = root.join("active");
    let id = std::fs::read_to_string(&path)
        .map_err(|e| Error::Configuration(format!("reading {}: {e}", path.display())))?;
    let id = id.trim().to_string();
    if id.is_empty() {
        return config(format!("{} is empty", path.display()));
    }
    Ok(id)
}

fn load_version(root: &Path, id: &str) -> Result<Version> {
    let directory = root.join(id);
    let sealed = std::fs::read(directory.join("key.enc")).map_err(|e| {
        Error::Configuration(format!("reading the sealed key for version {id}: {e}"))
    })?;
    let chain_pem = std::fs::read_to_string(directory.join("chain.pem"))
        .map_err(|e| Error::Configuration(format!("reading the chain for version {id}: {e}")))?;
    let meta: VersionMeta = serde_json::from_str(
        &std::fs::read_to_string(directory.join("meta.json")).map_err(|e| {
            Error::Configuration(format!("reading the metadata for version {id}: {e}"))
        })?,
    )
    .map_err(|e| Error::Configuration(format!("the metadata for version {id}: {e}")))?;

    let chain = x509::pem_to_der(&chain_pem)
        .map_err(|e| Error::Configuration(format!("the chain for version {id}: {e}")))?;
    let leaf = x509::parse_certificate(
        chain
            .first()
            .ok_or_else(|| Error::Configuration(format!("version {id} has an empty chain")))?,
    )
    .map_err(|e| Error::Configuration(format!("the leaf for version {id}: {e}")))?;

    Ok(Version {
        id: id.to_string(),
        meta,
        chain_pem,
        leaf,
        sealed,
    })
}

/// PKCS#8 DER from a PEM private key.
fn private_key_der(pem: &str) -> Result<Zeroizing<Vec<u8>>> {
    for marker in ["PRIVATE KEY"] {
        if pem.contains(marker) {
            let blocks = x509::pem_to_der(pem)
                .map_err(|e| Error::Configuration(format!("the private key: {e}")))?;
            return Ok(Zeroizing::new(
                blocks.into_iter().next().unwrap_or_default(),
            ));
        }
    }
    config("the private key must be PEM-encoded PKCS#8 (-----BEGIN PRIVATE KEY-----)")
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .map_err(|e| Error::Configuration(format!("writing {}: {e}", path.display())))
}

/// Write a file only the owner can read.
///
/// Least privilege, as O.2 requires: the sealed key is useless without the
/// key-encryption key, but there is no reason for anything else on the host to
/// be able to read it either.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    write_file(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Configuration(format!("securing {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> KeyEncryptionKey {
        use base64::Engine as _;
        KeyEncryptionKey::from_base64(
            &base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            "test",
        )
        .unwrap()
    }

    struct Temp(std::path::PathBuf);

    impl Temp {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "claim-signer-keystore-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Temp(path)
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `unwrap_err` would need `Debug` on the key types, and deriving that on
    /// anything holding key material is how key material ends up in a log.
    fn expect_err<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected this to fail"),
            Err(e) => e.to_string(),
        }
    }

    fn meta() -> VersionMeta {
        VersionMeta {
            algorithm: "ES256".into(),
            imported_at: "2026-08-26T00:00:00Z".into(),
            note: "test".into(),
        }
    }

    fn import(root: &Path, id: &str) {
        Keystore::import(
            root,
            &kek(),
            id,
            imagecore::c2pa::testpki::CLAIM_SIGNER_KEY_PEM,
            imagecore::c2pa::testpki::CLAIM_SIGNER_CHAIN_PEM,
            meta(),
        )
        .unwrap();
    }

    #[test]
    fn a_key_round_trips_through_the_keystore_and_signs() {
        let temp = Temp::new("roundtrip");
        import(&temp.0, "v1");
        Keystore::activate(&temp.0, "v1").unwrap();

        let store = Keystore::open(&temp.0, kek()).unwrap();
        assert_eq!(store.active().id, "v1");

        let message = b"a Sig_structure, more or less";
        let signature = store.sign(message).unwrap();
        assert_eq!(signature.len(), 64);
        imagecore::c2pa::verify::by_cose_algorithm(
            imagecore::c2pa::identity::alg::ES256,
            &store.active().leaf,
            message,
            &signature,
        )
        .expect("the signature should verify against the stored certificate");
    }

    #[test]
    fn the_key_is_never_stored_in_the_clear() {
        // The single most important property in this file, so it is asserted
        // against the bytes on disk rather than argued for in a comment.
        let temp = Temp::new("sealed");
        import(&temp.0, "v1");

        let sealed = std::fs::read(temp.0.join("v1/key.enc")).unwrap();
        let plaintext = private_key_der(imagecore::c2pa::testpki::CLAIM_SIGNER_KEY_PEM).unwrap();
        assert!(
            !sealed
                .windows(plaintext.len())
                .any(|window| window == plaintext.as_slice()),
            "the plaintext key must not appear in key.enc"
        );
        assert!(
            sealed.len() > plaintext.len(),
            "nonce and tag should be present"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_sealed_key_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let temp = Temp::new("perms");
        import(&temp.0, "v1");
        let mode = std::fs::metadata(temp.0.join("v1/key.enc"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn the_wrong_key_encryption_key_cannot_open_the_store() {
        use base64::Engine as _;
        let temp = Temp::new("wrong-kek");
        import(&temp.0, "v1");
        Keystore::activate(&temp.0, "v1").unwrap();

        let other = KeyEncryptionKey::from_base64(
            &base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
            "test",
        )
        .unwrap();
        let error = expect_err(Keystore::open(&temp.0, other));
        assert!(error.to_string().contains("did not decrypt"), "{error}");
    }

    #[test]
    fn a_sealed_key_moved_between_versions_does_not_decrypt() {
        // The version id is authenticated data, so lifting `key.enc` from a
        // retired version into the active one is caught rather than silently
        // signing with the wrong key.
        let temp = Temp::new("moved");
        import(&temp.0, "v1");
        import(&temp.0, "v2");
        std::fs::copy(temp.0.join("v1/key.enc"), temp.0.join("v2/key.enc")).unwrap();
        Keystore::activate(&temp.0, "v2").unwrap();

        let error = expect_err(Keystore::open(&temp.0, kek()));
        assert!(error.to_string().contains("did not decrypt"), "{error}");
    }

    #[test]
    fn a_tampered_ciphertext_is_refused() {
        let temp = Temp::new("tampered");
        import(&temp.0, "v1");
        Keystore::activate(&temp.0, "v1").unwrap();

        let path = temp.0.join("v1/key.enc");
        let mut sealed = std::fs::read(&path).unwrap();
        let at = sealed.len() / 2;
        sealed[at] ^= 0x01;
        std::fs::write(&path, &sealed).unwrap();

        assert!(Keystore::open(&temp.0, kek()).is_err());
    }

    #[test]
    fn a_key_that_does_not_match_its_certificate_is_caught_at_startup() {
        let temp = Temp::new("mismatch");
        // The TSA key with the claim signer's chain: both are valid, and they
        // do not go together.
        Keystore::import(
            &temp.0,
            &kek(),
            "v1",
            imagecore::c2pa::testpki::TSA_SIGNER_KEY_PEM,
            imagecore::c2pa::testpki::CLAIM_SIGNER_CHAIN_PEM,
            meta(),
        )
        .unwrap();
        Keystore::activate(&temp.0, "v1").unwrap();

        let error = expect_err(Keystore::open(&temp.0, kek()));
        assert!(
            error.to_string().contains("does not match the certificate"),
            "{error}"
        );
    }

    #[test]
    fn rotation_stages_a_version_before_switching_to_it() {
        let temp = Temp::new("rotate");
        import(&temp.0, "2026-01-signer");
        Keystore::activate(&temp.0, "2026-01-signer").unwrap();
        assert_eq!(
            Keystore::open(&temp.0, kek()).unwrap().active().id,
            "2026-01-signer"
        );

        // Staging the next credential does not change what is signing.
        import(&temp.0, "2027-01-signer");
        assert_eq!(
            Keystore::open(&temp.0, kek()).unwrap().active().id,
            "2026-01-signer"
        );

        Keystore::activate(&temp.0, "2027-01-signer").unwrap();
        assert_eq!(
            Keystore::open(&temp.0, kek()).unwrap().active().id,
            "2027-01-signer"
        );

        // And the retired version is still there, because images signed under
        // it are still out in the world.
        let versions = Keystore::versions(&temp.0).unwrap();
        assert_eq!(versions, vec!["2027-01-signer", "2026-01-signer"]);
    }

    #[test]
    fn activating_a_version_that_does_not_exist_is_refused() {
        let temp = Temp::new("missing");
        assert!(Keystore::activate(&temp.0, "nope").is_err());
    }

    #[test]
    fn a_ca_certificate_cannot_be_imported_as_a_signer() {
        let temp = Temp::new("ca");
        let error = expect_err(Keystore::import(
            &temp.0,
            &kek(),
            "v1",
            imagecore::c2pa::testpki::CLAIM_SIGNER_KEY_PEM,
            imagecore::c2pa::testpki::ISSUING_CA_PEM,
            meta(),
        ));
        assert!(error.to_string().contains("must not be a CA"), "{error}");
    }

    #[test]
    fn a_key_encryption_key_of_the_wrong_length_is_refused() {
        use base64::Engine as _;
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let error = expect_err(KeyEncryptionKey::from_base64(&short, "test"));
        assert!(error.to_string().contains("32 bytes"), "{error}");
    }
}
