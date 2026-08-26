//! The Backend subsystem: the only place a C2PA claim signing key exists.
//!
//! # What this is for
//!
//! The A10city Image Editor is a **Distributed** Generator Product in the C2PA
//! Conformance Program's terms. The browser is the Edge subsystem: it opens the
//! image, applies the edits, builds the assertions and the claim, and computes
//! the `Sig_structure`. This service is the Backend subsystem: it holds the
//! claim signing key, signs that structure, and fetches an RFC 3161 time-stamp
//! over the resulting signature.
//!
//! The split exists because Assurance Level 1 cannot be reached without it.
//! Objective O.2 requires the signing key to be encrypted at rest and in
//! memory, access-controlled by least privilege, and rotatable. A key compiled
//! into a WebAssembly module and served to every visitor satisfies none of
//! those, and no amount of obfuscation changes that.
//!
//! ```text
//!   browser (Edge)                        claim-signer (Backend)
//!   ─────────────────                     ──────────────────────────────
//!   decode, edit, encode
//!   build claim + assertions
//!   Sig_structure  ───── TLS 1.3 ─────▶   authenticate the caller (O.2)
//!   (a few hundred bytes;                 decrypt the key for one operation
//!    no pixels)                           sign
//!                                         ask the TSA to stamp the signature
//!                  ◀─── signature ─────   re-encrypt, zeroise, log
//!                       + TST
//!   assemble COSE_Sign1, embed
//! ```
//!
//! # Endpoints
//!
//! | Method | Path | Purpose |
//! |---|---|---|
//! | `GET` | `/v1/identity` | the public credential: chain, algorithm, key id, time-stamp budget |
//! | `POST` | `/v1/sign` | sign a `Sig_structure`, and stamp the result |
//! | `GET` | `/healthz` | liveness, with no authentication and no secrets |
//!
//! # Configuration
//!
//! Everything comes from the environment, so that a deployment is described by
//! its orchestration rather than by a file inside the image.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `CLAIM_SIGNER_BIND` | address to listen on (default `0.0.0.0:8443`) |
//! | `CLAIM_SIGNER_KEYSTORE` | directory holding the sealed signing keys |
//! | `CLAIM_SIGNER_KEK_FILE` / `CLAIM_SIGNER_KEK` | the key-encryption key, 32 Base64 bytes |
//! | `CLAIM_SIGNER_CLIENTS` | JSON file of `{ "<edge key id>": "<base64 secret>" }` |
//! | `CLAIM_SIGNER_TLS_CERT`, `CLAIM_SIGNER_TLS_KEY` | server certificate and key |
//! | `CLAIM_SIGNER_CLIENT_CA` | optional: require mutual TLS against this CA bundle |
//! | `CLAIM_SIGNER_TSA_URL` | RFC 3161 endpoint; unset disables time-stamping |
//! | `CLAIM_SIGNER_TIMESTAMP_BUDGET` | bytes the Edge should reserve (default 12288) |
//! | `CLAIM_SIGNER_ALLOW_PLAINTEXT` | development only: serve HTTP instead of TLS |
//!
//! # Subcommands
//!
//! ```text
//!   claim-signer serve                      run the service
//!   claim-signer import --id … --key … --chain …   stage a new credential
//!   claim-signer activate --id …            rotate onto a staged credential
//!   claim-signer versions                   list what the keystore holds
//! ```

mod auth;
mod keystore;
mod tsa;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use imagecore::c2pa::cose::TIMESTAMP_BUDGET;
use serde::{Deserialize, Serialize};
use tower_http::limit::RequestBodyLimitLayer;

use auth::Clients;
use keystore::{KeyEncryptionKey, Keystore, VersionMeta};
use tsa::Tsa;

/// The largest `Sig_structure` worth accepting.
///
/// A claim with a long ingredient chain and a three-deep certificate chain runs
/// to a few kilobytes. Anything approaching a megabyte is not a claim, and a
/// signing endpoint is exactly the kind of thing worth capping hard.
const MAX_BODY: usize = 256 * 1024;

struct Service {
    keystore: Keystore,
    clients: Clients,
    tsa: Option<Tsa>,
    timestamp_budget: usize,
}

type Shared = Arc<Service>;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "claim_signer=info,tower_http=warn".into()),
        )
        .json()
        .init();

    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            // Deliberately not `tracing::error!`: a configuration failure needs
            // to be legible in a container log before the JSON formatter is
            // something anyone is reading.
            eprintln!("claim-signer: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("serve") => serve().await,
        Some("import") => import(args.collect()),
        Some("activate") => activate(args.collect()),
        Some("versions") => versions(),
        Some("-h") | Some("--help") => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}'\n\n{}", usage())),
    }
}

fn usage() -> &'static str {
    "\
claim-signer — the Backend subsystem of the A10city Image Editor Generator Product

USAGE:
    claim-signer serve
    claim-signer import --id <ID> --key <FILE> --chain <FILE> [--algorithm ES256] [--note TEXT]
    claim-signer activate --id <ID>
    claim-signer versions

Configuration comes from the environment; see the module documentation."
}

/* ------------------------------------------------------------------------- */
/* Serving                                                                    */
/* ------------------------------------------------------------------------- */

async fn serve() -> Result<(), String> {
    let keystore_dir = env("CLAIM_SIGNER_KEYSTORE")?;
    let kek = KeyEncryptionKey::from_environment().map_err(|e| e.to_string())?;
    let keystore = Keystore::open(&keystore_dir, kek).map_err(|e| e.to_string())?;

    let clients_path = env("CLAIM_SIGNER_CLIENTS")?;
    let clients = Clients::from_json(
        &std::fs::read_to_string(&clients_path)
            .map_err(|e| format!("reading {clients_path}: {e}"))?,
    )?;

    let timestamp_budget = std::env::var("CLAIM_SIGNER_TIMESTAMP_BUDGET")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(TIMESTAMP_BUDGET);
    let tsa = std::env::var("CLAIM_SIGNER_TSA_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .map(|url| Tsa::new(url, std::time::Duration::from_secs(10)));

    let leaf = &keystore.active().leaf;
    tracing::info!(
        key_id = %keystore.active().id,
        algorithm = %keystore.active().meta.algorithm,
        subject = %leaf.subject,
        not_after = %leaf.not_after,
        assurance_level = ?leaf.c2pa_assurance_level,
        cpl_record = ?leaf.c2pa_cpl_record_id,
        claim_signing_eku = leaf.has_claim_signing_eku(),
        kek_source = keystore.kek_source(),
        clients = clients.len(),
        tsa = tsa.as_ref().map(Tsa::url).unwrap_or("none"),
        "claim-signer starting"
    );

    // Say so loudly rather than discovering it in a validator. A certificate
    // issued under the C2PA Certificate Policy carries both of these; one that
    // does not is a test credential, and a deployment running on a test
    // credential should know it is.
    if leaf.c2pa_assurance_level.is_none() {
        tracing::warn!(
            "the active certificate carries no c2pa-al extension: it was not issued under the \
             C2PA Certificate Policy, and manifests signed with it will not be recognised as \
             coming from a conforming Generator Product"
        );
    }
    if !leaf.has_claim_signing_eku() {
        tracing::warn!(
            "the active certificate does not assert c2pa-kp-claimSigning (1.3.6.1.4.1.62558.2.1)"
        );
    }

    let service = Arc::new(Service {
        keystore,
        clients,
        tsa,
        timestamp_budget,
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/identity", get(identity))
        .route("/v1/sign", post(sign))
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(30),
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(service);

    let bind: SocketAddr = std::env::var("CLAIM_SIGNER_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8443".into())
        .parse()
        .map_err(|e| format!("CLAIM_SIGNER_BIND: {e}"))?;

    if std::env::var("CLAIM_SIGNER_ALLOW_PLAINTEXT").is_ok() {
        // Objective O.5 requires TLS 1.3 between subsystems. This path exists
        // so a developer can run the service behind a local proxy, and it
        // announces itself every time.
        tracing::warn!(
            %bind,
            "serving plaintext HTTP: CLAIM_SIGNER_ALLOW_PLAINTEXT is set. This is not a \
             conformant configuration - objective O.5 requires TLS 1.3 between the Edge and \
             Backend subsystems."
        );
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|e| format!("binding {bind}: {e}"))?;
        axum::serve(listener, app)
            .await
            .map_err(|e| format!("serving: {e}"))
    } else {
        let config = tls_config()?;
        tracing::info!(%bind, "listening with TLS 1.3");
        axum_server::bind_rustls(
            bind,
            axum_server::tls_rustls::RustlsConfig::from_config(config),
        )
        .serve(app.into_make_service())
        .await
        .map_err(|e| format!("serving: {e}"))
    }
}

/// TLS 1.3 only, with optional mutual authentication.
///
/// Objective O.5, Assurance Level 1: "Network communication channels between
/// the subsystems SHALL be protected using TLS v1.3 (or higher) or an
/// equivalent protocol." Configured as the only permitted version rather than
/// as a minimum, so a downgrade is impossible rather than merely discouraged.
fn tls_config() -> Result<Arc<rustls::ServerConfig>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certificate_path = env("CLAIM_SIGNER_TLS_CERT")?;
    let key_path = env("CLAIM_SIGNER_TLS_KEY")?;

    let certificates: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(&certificate_path)
                .map_err(|e| format!("opening {certificate_path}: {e}"))?,
        ))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("reading {certificate_path}: {e}"))?;

    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(&key_path).map_err(|e| format!("opening {key_path}: {e}"))?,
    ))
    .map_err(|e| format!("reading {key_path}: {e}"))?
    .ok_or_else(|| format!("{key_path} holds no private key"))?;

    let builder = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);

    let mut config = match std::env::var("CLAIM_SIGNER_CLIENT_CA").ok() {
        Some(path) if !path.trim().is_empty() => {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_pemfile::certs(&mut std::io::BufReader::new(
                std::fs::File::open(&path).map_err(|e| format!("opening {path}: {e}"))?,
            )) {
                roots
                    .add(certificate.map_err(|e| format!("reading {path}: {e}"))?)
                    .map_err(|e| format!("adding a client CA from {path}: {e}"))?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| format!("building the client verifier: {e}"))?;
            tracing::info!(%path, "requiring mutual TLS");
            builder.with_client_cert_verifier(verifier)
        }
        _ => builder.with_no_client_auth(),
    }
    .with_single_cert(certificates, key)
    .map_err(|e| format!("the TLS certificate and key do not go together: {e}"))?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

/* ------------------------------------------------------------------------- */
/* Handlers                                                                   */
/* ------------------------------------------------------------------------- */

async fn healthz(State(service): State<Shared>) -> Json<serde_json::Value> {
    // No authentication and no secrets: a health check that needed a credential
    // would be one more secret in the orchestration for no benefit.
    Json(serde_json::json!({
        "status": "ok",
        "keyId": service.keystore.active().id,
        "notAfter": service.keystore.active().leaf.not_after,
        "timeStamping": service.tsa.is_some(),
    }))
}

/// The public half of the signing credential.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    /// PEM chain, leaf first, trust anchor omitted.
    chain_pem: String,
    algorithm: String,
    key_id: String,
    /// Bytes the Edge should reserve for a time-stamp token. Zero when no
    /// authority is configured, which is what tells the Edge not to reserve
    /// space it will never use.
    timestamp_budget: usize,
    assurance_level: Option<u32>,
    cpl_record_id: Option<String>,
    not_after: String,
}

async fn identity(State(service): State<Shared>) -> Json<Identity> {
    let active = service.keystore.active();
    Json(Identity {
        chain_pem: active.chain_pem.clone(),
        algorithm: active.meta.algorithm.clone(),
        key_id: active.id.clone(),
        timestamp_budget: if service.tsa.is_some() {
            service.timestamp_budget
        } else {
            0
        },
        assurance_level: active.leaf.c2pa_assurance_level,
        cpl_record_id: active.leaf.c2pa_cpl_record_id.clone(),
        not_after: active.leaf.not_after.clone(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignRequestBody {
    /// Base64 of the `Sig_structure` to sign.
    to_be_signed: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignResponseBody {
    signature: String,
    /// Base64 DER `TimeStampToken`, absent when none could be obtained.
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_token: Option<String>,
    key_id: String,
    /// Why there is no time-stamp, when there is none. Reported rather than
    /// left to inference: the Edge shows the user that the credential will stop
    /// validating when the certificate expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_error: Option<String>,
}

/// Sign a `Sig_structure` and, where an authority is configured, stamp it.
async fn sign(State(service): State<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let header = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body is too large",
            )
        }
    };

    // Authenticate before parsing, so a malformed body from an unauthenticated
    // caller costs nothing but a MAC computation.
    let client = match service.clients.authenticate(
        header.as_deref(),
        parts.method.as_str(),
        parts.uri.path(),
        &body,
        auth::now(),
    ) {
        Ok(client) => client,
        Err(denied) => {
            tracing::warn!(reason = %denied.detail(), "refused a signing request");
            return problem(StatusCode::UNAUTHORIZED, denied.public_message());
        }
    };

    let parsed: SignRequestBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &format!("malformed request: {e}")),
    };
    let to_be_signed = match base64::engine::general_purpose::STANDARD.decode(&parsed.to_be_signed)
    {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "toBeSigned must be non-empty Base64",
            )
        }
    };

    let service = service.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let signature = service.keystore.sign(&to_be_signed)?;
        let stamped = match &service.tsa {
            Some(tsa) => match tsa.stamp(&signature) {
                Ok(token) => (Some(token), None),
                // A TSA outage must not stop people saving their photographs.
                // The credential is written without a stamp, the response says
                // so, and the interface passes that on.
                Err(why) => (None, Some(why)),
            },
            None => (None, None),
        };
        Ok::<_, keystore::Error>((signature, stamped.0, stamped.1, service))
    })
    .await;

    let (signature, token, timestamp_error, service) = match outcome {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "signing failed");
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "signing failed");
        }
        Err(e) => {
            tracing::error!(error = %e, "the signing task did not complete");
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "signing failed");
        }
    };

    if let Some(why) = &timestamp_error {
        tracing::warn!(error = %why, "no time-stamp was obtained");
    }

    // The audit record. Not the claim, and not the signature: a digest of what
    // was signed, which is enough to correlate a manifest with a request and
    // nothing more.
    tracing::info!(
        client = %client,
        key_id = %service.keystore.active().id,
        digest = %hex(&sha256(&signature)),
        time_stamped = token.is_some(),
        "signed a claim"
    );

    let engine = base64::engine::general_purpose::STANDARD;
    Json(SignResponseBody {
        signature: engine.encode(&signature),
        timestamp_token: token.map(|token| engine.encode(token)),
        key_id: service.keystore.active().id.clone(),
        timestamp_error,
    })
    .into_response()
}

fn problem(status: StatusCode, detail: &str) -> Response {
    (status, Json(serde_json::json!({ "error": detail }))).into_response()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/* ------------------------------------------------------------------------- */
/* Key rotation                                                               */
/* ------------------------------------------------------------------------- */

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|at| args.get(at + 1))
        .cloned()
}

fn import(args: Vec<String>) -> Result<(), String> {
    let root = env("CLAIM_SIGNER_KEYSTORE")?;
    let kek = KeyEncryptionKey::from_environment().map_err(|e| e.to_string())?;

    let id = flag(&args, "--id").ok_or("import needs --id")?;
    let key_path = flag(&args, "--key").ok_or("import needs --key")?;
    let chain_path = flag(&args, "--chain").ok_or("import needs --chain")?;
    let algorithm = flag(&args, "--algorithm").unwrap_or_else(|| "ES256".into());
    let note = flag(&args, "--note").unwrap_or_default();

    let meta = VersionMeta {
        algorithm,
        imported_at: imagecore::c2pa::clock::to_rfc3339(auth::now()),
        note,
    };

    Keystore::import(
        &root,
        &kek,
        &id,
        &std::fs::read_to_string(&key_path).map_err(|e| format!("reading {key_path}: {e}"))?,
        &std::fs::read_to_string(&chain_path).map_err(|e| format!("reading {chain_path}: {e}"))?,
        meta,
    )
    .map_err(|e| e.to_string())?;

    println!(
        "imported {id}. It is not signing yet — run `claim-signer activate --id {id}` when you \
         are ready to rotate onto it."
    );
    Ok(())
}

fn activate(args: Vec<String>) -> Result<(), String> {
    let root = env("CLAIM_SIGNER_KEYSTORE")?;
    let id = flag(&args, "--id").ok_or("activate needs --id")?;
    Keystore::activate(&root, &id).map_err(|e| e.to_string())?;
    println!("{id} is now the active signing credential. Restart the service to pick it up.");
    Ok(())
}

fn versions() -> Result<(), String> {
    let root = env("CLAIM_SIGNER_KEYSTORE")?;
    let active = std::fs::read_to_string(std::path::Path::new(&root).join("active"))
        .unwrap_or_default()
        .trim()
        .to_string();
    for id in Keystore::versions(&root).map_err(|e| e.to_string())? {
        let marker = if id == active { "* " } else { "  " };
        println!("{marker}{id}");
    }
    Ok(())
}
