//! Building and validating C2PA manifests.
//!
//! # The circular dependency, and how it is broken
//!
//! A standard manifest must carry a hard binding: a `c2pa.hash.data` assertion
//! hashing the finished file. But the manifest lives *inside* that file, so its
//! own bytes cannot be part of the hash — and its size is not known until it is
//! built, which cannot happen until the hash exists.
//!
//! Section 10.4 of the specification breaks the loop with exclusion ranges and
//! fixed-width placeholders. This module does it in two renders:
//!
//! ```text
//!   render 1     everything real except: hash = 32 zero bytes
//!                                        exclusion = (0, 0)
//!                                        signature = 64 zero bytes
//!                       │
//!                       ├── gives the store's exact final size, because every
//!                       │   placeholder is the same width as the real value
//!                       ▼
//!   measure      exclusion = (insertion offset, embedded length)
//!                hash      = SHA-256 of the file with that range removed,
//!                            which is just head ++ tail
//!                       │
//!                       ▼
//!   render 2     the same manifest with real values substituted in, asserted
//!                to be byte-for-byte the same length as render 1
//! ```
//!
//! Three properties make the placeholders exact, and each is enforced rather
//! than assumed:
//!
//! - `start` and `length` are written as 32-bit CBOR integers whatever their
//!   value ([`cbor::Value::Uint32`]). Section 18.5.2 asks for precisely this.
//! - SHA-256 is always 32 bytes and an ES256 signature always 64.
//! - Every value that would otherwise vary between renders — timestamps, the
//!   instance ID, the manifest URN — is computed once by the caller and passed
//!   in, so the two renders differ only where they are meant to.
//!
//! The final `debug_assert_eq!` on the two lengths is the backstop. If a future
//! change breaks one of those properties, it fails there rather than producing
//! a manifest whose offsets are quietly wrong.

use sha2::{Digest, Sha256};

use super::cbor::Value;
use super::jumbf::{self, Child, Superbox};
use super::{cose, jpegxt, signer, x509};

/// The hash algorithm identifier used throughout, from the C2PA registry.
const ALG: &str = "sha256";

/// Assertion labels (C2PA 2.2, chapter 18).
const LABEL_ASSERTIONS: &str = "c2pa.assertions";
const LABEL_CLAIM: &str = "c2pa.claim.v2";
const LABEL_SIGNATURE: &str = "c2pa.signature";
const LABEL_ACTIONS: &str = "c2pa.actions.v2";
const LABEL_HASH_DATA: &str = "c2pa.hash.data";
const LABEL_INGREDIENT: &str = "c2pa.ingredient.v3";
const LABEL_THUMBNAIL: &str = "c2pa.thumbnail.claim";
/// Older files use these; the validator accepts them, the generator never
/// writes them.
const LABEL_CLAIM_V1: &str = "c2pa.claim";
const LABEL_ACTIONS_V1: &str = "c2pa.actions";

pub type Result<T> = std::result::Result<T, String>;

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// A `hashed-uri-map`: where a box is and what it hashes to.
fn hashed_uri(url: &str, hash: &[u8]) -> Value {
    Value::Map(vec![
        (Value::text("url"), Value::text(url)),
        (Value::text("hash"), Value::bytes(hash.to_vec())),
    ])
}

/// The hashed URI for an assertion, whose hash covers the superbox contents but
/// not its header (section 8.4.2.3).
fn assertion_uri(assertion: &Superbox) -> Value {
    hashed_uri(
        &format!("self#jumbf={LABEL_ASSERTIONS}/{}", assertion.label),
        &sha256(&assertion.contents_for_hash()),
    )
}

/* ------------------------------------------------------------------------- */
/* Request                                                                    */
/* ------------------------------------------------------------------------- */

#[derive(Clone, Debug)]
pub struct GeneratorInfo {
    pub name: String,
    pub version: String,
}

impl GeneratorInfo {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("name"), Value::text(self.name.clone())),
            (Value::text("version"), Value::text(self.version.clone())),
        ])
    }
}

/// One entry of the `c2pa.actions.v2` assertion.
#[derive(Clone, Debug)]
pub struct Action {
    /// A predefined name such as `c2pa.cropped`, or an entity-specific one.
    pub action: String,
    /// Free text shown to a person; important for entity-specific actions.
    pub description: Option<String>,
    /// Extra `parameters-map-v2` entries, e.g. the new dimensions of a resize.
    pub parameters: Vec<(String, Value)>,
}

impl Action {
    pub fn new(action: impl Into<String>) -> Self {
        Action {
            action: action.into(),
            description: None,
            parameters: Vec::new(),
        }
    }

    pub fn describe(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn param(mut self, key: impl Into<String>, value: Value) -> Self {
        self.parameters.push((key.into(), value));
        self
    }
}

/// The asset that was opened to produce this one.
#[derive(Clone, Debug, Default)]
pub struct Parent {
    pub title: String,
    pub format: String,
    pub instance_id: String,
    /// The parent's own manifest store, when it had one.
    pub store: Option<ParentStore>,
}

#[derive(Clone, Debug)]
pub struct ParentStore {
    /// The raw JUMBF store lifted out of the parent file.
    pub bytes: Vec<u8>,
    /// Label of the parent's active manifest, used to build URIs into it.
    pub active_manifest: String,
    /// What validating the parent produced, recorded in `validationResults`.
    pub status: StatusCodes,
}

/// Everything needed to produce a manifest, with every non-deterministic value
/// supplied by the caller.
///
/// The host owning the clock and the randomness is not an accident of the
/// wasm target having neither: it is also what makes the two renders described
/// at the top of this module produce identical bytes, and what makes the tests
/// reproducible.
#[derive(Clone, Debug)]
pub struct SignRequest {
    pub title: String,
    pub generator: GeneratorInfo,
    /// RFC 3339 timestamp for every action's `when`.
    pub now: String,
    /// `xmpMM:InstanceID` for the output.
    pub instance_id: String,
    /// `urn:c2pa:<uuid>`, the manifest's label.
    pub manifest_id: String,
    pub actions: Vec<Action>,
    pub parent: Option<Parent>,
    /// A JPEG thumbnail of the result, for viewers that show one.
    pub thumbnail: Option<Vec<u8>>,
}

/* ------------------------------------------------------------------------- */
/* Building                                                                   */
/* ------------------------------------------------------------------------- */

/// The parts of a manifest that do not change between renders.
struct Blueprint<'a> {
    request: &'a SignRequest,
    /// Parent manifests copied forward, so the chain of provenance stays
    /// walkable from the finished file alone.
    inherited: Vec<Superbox>,
    /// `c2pa.ingredient.v3`, when something was opened.
    ingredient: Option<Superbox>,
    thumbnail: Option<Superbox>,
}

impl<'a> Blueprint<'a> {
    fn new(request: &'a SignRequest) -> Result<Self> {
        let mut inherited = Vec::new();
        let mut ingredient = None;

        if let Some(parent) = &request.parent {
            // Copy the parent's manifests into the new store before building
            // the ingredient, because the ingredient's hashed URIs point at
            // them and must hash what will actually be there.
            if let Some(store) = &parent.store {
                let parsed = jumbf::parse(&store.bytes)
                    .map_err(|e| format!("the parent manifest store is unreadable: {e}"))?;
                for manifest in parsed.child_boxes() {
                    inherited.push(manifest.clone());
                }
            }
            ingredient = Some(build_ingredient(parent, &inherited)?);
        }

        let thumbnail = request
            .thumbnail
            .as_ref()
            .map(|bytes| jumbf::embedded_file_box(LABEL_THUMBNAIL, "image/jpeg", bytes.clone()));

        Ok(Blueprint {
            request,
            inherited,
            ingredient,
            thumbnail,
        })
    }

    /// Render the whole store. `hash` and `exclusion` fill the hard binding;
    /// `sign` turns claim bytes into a `COSE_Sign1`.
    fn render(
        &self,
        hash: &[u8],
        exclusion: (u32, u32),
        sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let mut assertions: Vec<Superbox> = Vec::new();
        if let Some(thumbnail) = &self.thumbnail {
            assertions.push(thumbnail.clone());
        }
        if let Some(ingredient) = &self.ingredient {
            assertions.push(ingredient.clone());
        }
        assertions.push(self.build_actions());
        assertions.push(build_hash_data(hash, exclusion));

        let mut store_box = Superbox::new(jumbf::UUID_ASSERTION_STORE, LABEL_ASSERTIONS);
        for assertion in &assertions {
            store_box.push(Child::Super(assertion.clone()));
        }

        let claim = self.build_claim(&assertions);
        let claim_bytes = claim.encode();
        let signature = sign(&claim_bytes)?;

        let manifest = Superbox::new(jumbf::UUID_MANIFEST, self.request.manifest_id.clone())
            .with_child(Child::Super(store_box))
            .with_child(Child::Super(Superbox::cbor(
                jumbf::UUID_CLAIM,
                LABEL_CLAIM,
                claim_bytes,
            )))
            .with_child(Child::Super(Superbox::cbor(
                jumbf::UUID_SIGNATURE,
                LABEL_SIGNATURE,
                signature,
            )));

        let mut store = Superbox::new(jumbf::UUID_MANIFEST_STORE, "c2pa");
        for parent in &self.inherited {
            store.push(Child::Super(parent.clone()));
        }
        // The active manifest is the last one in the store (section 11.1.2).
        store.push(Child::Super(manifest));

        Ok(store.to_bytes())
    }

    fn build_actions(&self) -> Superbox {
        let mut items = Vec::new();

        for action in &self.request.actions {
            let mut fields = vec![
                (Value::text("action"), Value::text(action.action.clone())),
                (
                    Value::text("when"),
                    Value::datetime(self.request.now.clone()),
                ),
                // v2 lets the software agent be named once in `softwareAgents`
                // and referenced by index, rather than repeated per action.
                (Value::text("softwareAgentIndex"), Value::Uint(0)),
            ];

            if let Some(description) = &action.description {
                fields.push((Value::text("description"), Value::text(description.clone())));
            }

            let mut parameters: Vec<(Value, Value)> = action
                .parameters
                .iter()
                .map(|(k, v)| (Value::text(k.clone()), v.clone()))
                .collect();

            // Section 15.10.3.2.2: a `c2pa.opened` action must point at exactly
            // one ingredient assertion whose relationship is `parentOf`, or the
            // whole claim is rejected. Wiring it here, from the same box that
            // will be written, keeps the two from drifting apart.
            if action.action == "c2pa.opened" {
                if let Some(ingredient) = &self.ingredient {
                    parameters.push((
                        Value::text("ingredients"),
                        Value::Array(vec![assertion_uri(ingredient)]),
                    ));
                }
            }

            if !parameters.is_empty() {
                fields.push((Value::text("parameters"), Value::Map(parameters)));
            }

            items.push(Value::Map(fields));
        }

        let actions = Value::Map(vec![
            (Value::text("actions"), Value::Array(items)),
            (
                Value::text("softwareAgents"),
                Value::Array(vec![self.request.generator.to_value()]),
            ),
            // The editor knows every operation it performed, so it can say so.
            // Section 18.10: this asserts nothing else happened off the record.
            (Value::text("allActionsIncluded"), Value::Bool(true)),
        ]);

        Superbox::cbor(jumbf::UUID_CBOR, LABEL_ACTIONS, actions.encode())
    }

    fn build_claim(&self, assertions: &[Superbox]) -> Value {
        Value::Map(vec![
            (
                Value::text("instanceID"),
                Value::text(self.request.instance_id.clone()),
            ),
            (
                Value::text("claim_generator_info"),
                self.request.generator.to_value(),
            ),
            (
                Value::text("signature"),
                Value::text(format!("self#jumbf={LABEL_SIGNATURE}")),
            ),
            (
                Value::text("created_assertions"),
                Value::Array(assertions.iter().map(assertion_uri).collect()),
            ),
            (
                Value::text("dc:title"),
                Value::text(self.request.title.clone()),
            ),
            // Sets the hash algorithm for every hashed URI and data hash in
            // this claim that does not override it.
            (Value::text("alg"), Value::text(ALG)),
        ])
        // Note the absence of `dc:format`: claim v2 dropped it (section 10.2.2).
    }
}

/// The `c2pa.hash.data` hard binding.
fn build_hash_data(hash: &[u8], exclusion: (u32, u32)) -> Superbox {
    let assertion = Value::Map(vec![
        (
            Value::text("exclusions"),
            Value::Array(vec![Value::Map(vec![
                // Fixed-width so patching cannot change the encoded size.
                (Value::text("start"), Value::Uint32(exclusion.0)),
                (Value::text("length"), Value::Uint32(exclusion.1)),
            ])]),
        ),
        (Value::text("alg"), Value::text(ALG)),
        (Value::text("hash"), Value::bytes(hash.to_vec())),
        // Required by the schema even when empty (section 18.5.2).
        (Value::text("pad"), Value::bytes(Vec::new())),
        (Value::text("name"), Value::text("jumbf manifest")),
    ]);

    Superbox::cbor(jumbf::UUID_CBOR, LABEL_HASH_DATA, assertion.encode())
}

/// The `c2pa.ingredient.v3` assertion describing what was opened.
fn build_ingredient(parent: &Parent, inherited: &[Superbox]) -> Result<Superbox> {
    let mut fields = vec![
        (Value::text("dc:title"), Value::text(parent.title.clone())),
        (Value::text("dc:format"), Value::text(parent.format.clone())),
        // The editor opens one image and edits it, so the relationship is
        // always parentOf rather than componentOf.
        (Value::text("relationship"), Value::text("parentOf")),
        (
            Value::text("instanceID"),
            Value::text(parent.instance_id.clone()),
        ),
    ];

    if let Some(store) = &parent.store {
        let manifest = inherited
            .iter()
            .find(|m| m.label == store.active_manifest)
            .ok_or_else(|| {
                format!(
                    "the parent's active manifest '{}' is not in its store",
                    store.active_manifest
                )
            })?;

        // URIs into an inherited manifest are absolute — they start at the
        // store root — because they leave the current manifest (section 8.4.1).
        let manifest_url = format!("self#jumbf=/c2pa/{}", manifest.label);
        fields.push((
            Value::text("activeManifest"),
            hashed_uri(&manifest_url, &sha256(&manifest.contents_for_hash())),
        ));

        if let Some(signature) = manifest.child(LABEL_SIGNATURE) {
            fields.push((
                Value::text("claimSignature"),
                hashed_uri(
                    &format!("{manifest_url}/{LABEL_SIGNATURE}"),
                    &sha256(&signature.contents_for_hash()),
                ),
            ));
        }

        fields.push((
            Value::text("validationResults"),
            Value::Map(vec![(
                Value::text("activeManifest"),
                store.status.to_value(),
            )]),
        ));
    }

    Ok(Superbox::cbor(
        jumbf::UUID_CBOR,
        LABEL_INGREDIENT,
        Value::Map(fields).encode(),
    ))
}

/// What signing produced.
#[derive(Debug)]
pub struct Signed {
    pub jpeg: Vec<u8>,
    /// Size of the embedded manifest store, before APP11 framing.
    pub manifest_len: usize,
    /// Total bytes the credential added to the file.
    pub embedded_len: usize,
}

/// Sign a JPEG: build a manifest for it, and embed the result.
pub fn sign_jpeg(jpeg: &[u8], request: &SignRequest) -> Result<Signed> {
    let credentials = signer::load()?;
    let blueprint = Blueprint::new(request)?;

    // Render 1 measures. Placeholders are the same width as real values, so
    // this size is final.
    let placeholder_signature = cose::placeholder(&credentials.chain).map_err(|e| e.to_string())?;
    let measured = blueprint.render(&[0u8; 32], (0, 0), &|_| Ok(placeholder_signature.clone()))?;

    let plan = jpegxt::plan_insertion(jpeg).map_err(|e| e.to_string())?;
    let embedded_len = jpegxt::embedded_length(measured.len());

    let exclusion = (
        u32::try_from(plan.offset).map_err(|_| "the JPEG is too large to sign".to_string())?,
        u32::try_from(embedded_len)
            .map_err(|_| "the manifest is too large to embed".to_string())?,
    );

    // The hard binding covers the file with the manifest's range removed, and
    // that range is precisely where the manifest is about to go — so the bytes
    // to hash are the file either side of the insertion point.
    let mut binding = Sha256::new();
    binding.update(&plan.stripped[..plan.offset]);
    binding.update(&plan.stripped[plan.offset..]);
    let hash = binding.finalize().to_vec();

    // Render 2 substitutes the real values in.
    let store = blueprint.render(&hash, exclusion, &|claim_bytes| {
        cose::sign(claim_bytes, &credentials.key, &credentials.chain).map_err(|e| e.to_string())
    })?;

    // If this ever fires, a placeholder stopped matching the width of the value
    // it stands in for, and every offset in the hard binding is wrong.
    debug_assert_eq!(
        store.len(),
        measured.len(),
        "manifest size changed between renders"
    );
    if store.len() != measured.len() {
        return Err("the manifest changed size while being signed".into());
    }

    let signed = jpegxt::embed(&plan, &store).map_err(|e| e.to_string())?;
    Ok(Signed {
        jpeg: signed,
        manifest_len: store.len(),
        embedded_len,
    })
}

/* ------------------------------------------------------------------------- */
/* Validation                                                                 */
/* ------------------------------------------------------------------------- */

/// A `status-codes-map` (section 15.2.1).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct StatusCodes {
    pub success: Vec<Status>,
    pub informational: Vec<Status>,
    pub failure: Vec<Status>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Status {
    pub code: String,
    pub explanation: String,
}

impl Status {
    fn new(code: &str, explanation: impl Into<String>) -> Self {
        Status {
            code: code.to_string(),
            explanation: explanation.into(),
        }
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("code"), Value::text(self.code.clone())),
            (
                Value::text("explanation"),
                Value::text(self.explanation.clone()),
            ),
        ])
    }
}

impl StatusCodes {
    fn to_value(&self) -> Value {
        let list = |items: &[Status]| Value::Array(items.iter().map(Status::to_value).collect());
        Value::Map(vec![
            (Value::text("success"), list(&self.success)),
            (Value::text("informational"), list(&self.informational)),
            (Value::text("failure"), list(&self.failure)),
        ])
    }

    pub fn is_valid(&self) -> bool {
        self.failure.is_empty()
    }
}

/// One action, as read back out of a manifest.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadAction {
    pub action: String,
    pub when: String,
    pub description: String,
    pub software_agent: String,
}

/// What a manifest says, and what checking it produced.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestReport {
    pub label: String,
    pub title: String,
    pub instance_id: String,
    pub generator: String,
    pub claim_version: u8,
    pub actions: Vec<ReadAction>,
    pub ingredients: Vec<IngredientReport>,
    pub assertion_labels: Vec<String>,
    pub signature: SignatureReport,
    /// A JPEG thumbnail from `c2pa.thumbnail.claim`, if present. Skipped when
    /// serialising: a byte array in JSON would be huge and unusable, so it
    /// reaches the UI as a Blob through its own accessor instead.
    #[serde(skip)]
    pub thumbnail: Option<Vec<u8>>,
    pub status: StatusCodes,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureReport {
    pub algorithm: String,
    pub issuer: String,
    pub subject: String,
    pub subject_organisation: String,
    pub not_before: String,
    pub not_after: String,
    pub time_stamped: bool,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngredientReport {
    pub title: String,
    pub format: String,
    pub relationship: String,
    pub has_manifest: bool,
}

/// The result of inspecting a file.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    /// The manifest that describes the file as it is now: the last in the store.
    pub active: ManifestReport,
    /// Every manifest in the store, oldest first — the provenance chain.
    pub chain: Vec<ManifestReport>,
    /// Raw store bytes, so a signed export can carry the chain forward. Kept
    /// out of the JSON for the same reason as the thumbnail.
    #[serde(skip)]
    pub store: Vec<u8>,
    pub store_len: usize,
}

impl ValidationReport {
    /// A `valid` flag alongside the report, so the UI does not have to
    /// re-derive the rule from the status arrays.
    pub fn to_json(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(map) = value.as_object_mut() {
            map.insert("valid".into(), serde_json::Value::Bool(self.is_valid()));
        }
        value.to_string()
    }

    /// Whether the file passed every check that was applied.
    ///
    /// Trust is deliberately not part of this. A validator with no trust anchor
    /// store cannot say whether a signer should be believed, only whether the
    /// bytes are intact and the signature is internally consistent.
    pub fn is_valid(&self) -> bool {
        self.active.status.is_valid()
    }
}

/// Read and check the Content Credentials in a JPEG.
///
/// `Ok(None)` means the file simply has none.
pub fn read_jpeg(jpeg: &[u8]) -> Result<Option<ValidationReport>> {
    let Some(embedded) = jpegxt::extract(jpeg).map_err(|e| e.to_string())? else {
        return Ok(None);
    };

    let store = jumbf::parse(&embedded.store)
        .map_err(|e| format!("the manifest store is unreadable: {e}"))?;

    let manifests: Vec<&Superbox> = store
        .child_boxes()
        .filter(|b| b.uuid == jumbf::UUID_MANIFEST || b.uuid == jumbf::UUID_UPDATE_MANIFEST)
        .collect();

    if manifests.is_empty() {
        return Err("the manifest store contains no manifests".into());
    }

    let mut chain = Vec::new();
    for manifest in &manifests {
        chain.push(inspect(manifest));
    }

    // The active manifest is the last one, and it is the only one whose hard
    // binding describes *this* file. Earlier manifests describe the ingredients
    // they came from, so re-checking their bindings here would be meaningless.
    let active_index = chain.len() - 1;
    let binding = check_hard_binding(jpeg, manifests[active_index], &embedded);
    let active_status = &mut chain[active_index].status;
    active_status.success.extend(binding.success);
    active_status.informational.extend(binding.informational);
    active_status.failure.extend(binding.failure);

    let active = chain[active_index].clone();
    Ok(Some(ValidationReport {
        active,
        chain,
        store: embedded.store,
        store_len: embedded.length,
    }))
}

/// Read one manifest and check everything internal to it: that each assertion
/// hashes to what the claim says, and that the claim matches its signature.
fn inspect(manifest: &Superbox) -> ManifestReport {
    let mut status = StatusCodes::default();
    let mut report = ManifestReport {
        label: manifest.label.clone(),
        title: String::new(),
        instance_id: String::new(),
        generator: String::new(),
        claim_version: 2,
        actions: Vec::new(),
        ingredients: Vec::new(),
        assertion_labels: Vec::new(),
        signature: SignatureReport::default(),
        thumbnail: None,
        status: StatusCodes::default(),
    };

    let claim_box = manifest
        .child(LABEL_CLAIM)
        .inspect(|_| report.claim_version = 2)
        .or_else(|| {
            manifest.child(LABEL_CLAIM_V1).inspect(|_| {
                report.claim_version = 1;
            })
        });

    let Some(claim_box) = claim_box else {
        status
            .failure
            .push(Status::new("claim.missing", "the manifest has no claim"));
        report.status = status;
        return report;
    };

    let Some(claim_bytes) = claim_box.cbor_payload() else {
        status.failure.push(Status::new(
            "claim.cbor.invalid",
            "the claim box holds no CBOR",
        ));
        report.status = status;
        return report;
    };

    let claim = match super::cbor::decode(claim_bytes) {
        Ok(claim) => claim,
        Err(e) => {
            status
                .failure
                .push(Status::new("claim.cbor.invalid", e.to_string()));
            report.status = status;
            return report;
        }
    };

    report.title = claim
        .get("dc:title")
        .and_then(Value::as_text)
        .unwrap_or_default()
        .to_string();
    report.instance_id = claim
        .get("instanceID")
        .and_then(Value::as_text)
        .unwrap_or_default()
        .to_string();
    report.generator = describe_generator(&claim);

    let assertion_store = manifest.child(LABEL_ASSERTIONS);
    if let Some(assertions) = assertion_store {
        report.assertion_labels = assertions.child_boxes().map(|b| b.label.clone()).collect();
        report.thumbnail = assertions
            .child(LABEL_THUMBNAIL)
            .and_then(|b| b.embedded_file().map(|(_, data)| data.to_vec()));
        read_actions(assertions, &mut report);
        read_ingredients(assertions, &mut report);
    } else {
        status.failure.push(Status::new(
            "assertion.missing",
            "the manifest has no assertion store",
        ));
    }

    check_assertion_hashes(&claim, assertion_store, &mut status);
    check_signature(manifest, claim_bytes, &mut report, &mut status);

    // A standard manifest must carry exactly one hard binding (section 11.2.1).
    if manifest.uuid == jumbf::UUID_MANIFEST
        && !report
            .assertion_labels
            .iter()
            .any(|label| label.starts_with("c2pa.hash."))
    {
        status.failure.push(Status::new(
            "claim.hardBindings.missing",
            "a standard manifest must contain a hard binding",
        ));
    }

    report.status = status;
    report
}

fn describe_generator(claim: &Value) -> String {
    // Claim v2 has a single generator-info-map; v1 had an array plus a
    // free-text `claim_generator` string.
    let info = claim.get("claim_generator_info");
    let map = match info {
        Some(Value::Array(items)) => items.first(),
        other => other,
    };

    if let Some(map) = map {
        let name = map.get("name").and_then(Value::as_text).unwrap_or_default();
        let version = map.get("version").and_then(Value::as_text);
        if !name.is_empty() {
            return match version {
                Some(version) => format!("{name} {version}"),
                None => name.to_string(),
            };
        }
    }

    claim
        .get("claim_generator")
        .and_then(Value::as_text)
        .unwrap_or("unknown")
        .to_string()
}

fn read_actions(assertions: &Superbox, report: &mut ManifestReport) {
    let actions_box = assertions
        .child(LABEL_ACTIONS)
        .or_else(|| assertions.child(LABEL_ACTIONS_V1));
    let Some(decoded) = actions_box
        .and_then(Superbox::cbor_payload)
        .and_then(|bytes| super::cbor::decode(bytes).ok())
    else {
        return;
    };

    // v2 names software agents once at the top and refers to them by index.
    let agents: Vec<String> = decoded
        .get("softwareAgents")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|agent| {
                    let name = agent.get("name").and_then(Value::as_text).unwrap_or("");
                    match agent.get("version").and_then(Value::as_text) {
                        Some(version) => format!("{name} {version}"),
                        None => name.to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let Some(items) = decoded.get("actions").and_then(Value::as_array) else {
        return;
    };

    for item in items {
        let software_agent = match item.get("softwareAgentIndex").and_then(Value::as_u64) {
            Some(index) => agents.get(index as usize).cloned().unwrap_or_default(),
            // v1 wrote a plain string here; v2 allows an inline generator map.
            None => match item.get("softwareAgent") {
                Some(Value::Text(name)) => name.clone(),
                Some(map) => map
                    .get("name")
                    .and_then(Value::as_text)
                    .unwrap_or_default()
                    .to_string(),
                None => String::new(),
            },
        };

        report.actions.push(ReadAction {
            action: item
                .get("action")
                .and_then(Value::as_text)
                .unwrap_or("c2pa.unknown")
                .to_string(),
            when: item
                .get("when")
                .and_then(Value::as_text)
                .unwrap_or_default()
                .to_string(),
            description: item
                .get("description")
                .or_else(|| item.get("parameters").and_then(|p| p.get("description")))
                .and_then(Value::as_text)
                .unwrap_or_default()
                .to_string(),
            software_agent,
        });
    }
}

fn read_ingredients(assertions: &Superbox, report: &mut ManifestReport) {
    for assertion in assertions.child_boxes() {
        if !assertion.label.starts_with("c2pa.ingredient") {
            continue;
        }
        let Some(decoded) = assertion
            .cbor_payload()
            .and_then(|bytes| super::cbor::decode(bytes).ok())
        else {
            continue;
        };
        report.ingredients.push(IngredientReport {
            title: decoded
                .get("dc:title")
                .and_then(Value::as_text)
                .unwrap_or_default()
                .to_string(),
            format: decoded
                .get("dc:format")
                .and_then(Value::as_text)
                .unwrap_or_default()
                .to_string(),
            relationship: decoded
                .get("relationship")
                .and_then(Value::as_text)
                .unwrap_or_default()
                .to_string(),
            has_manifest: decoded.get("activeManifest").is_some(),
        });
    }
}

/// Every assertion the claim references must be present and hash to the value
/// the claim recorded (section 15.10.3).
fn check_assertion_hashes(claim: &Value, assertions: Option<&Superbox>, status: &mut StatusCodes) {
    let referenced: Vec<&Value> = claim
        .get("created_assertions")
        .or_else(|| claim.get("assertions")) // v1
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default();

    let gathered: Vec<&Value> = claim
        .get("gathered_assertions")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default();

    let mut mismatched = 0usize;
    let mut checked = 0usize;

    for entry in referenced.into_iter().chain(gathered) {
        let Some(url) = entry.get("url").and_then(Value::as_text) else {
            continue;
        };
        let Some(expected) = entry.get("hash").and_then(Value::as_bytes) else {
            continue;
        };

        // Only self#jumbf references inside this manifest are resolvable here.
        let path = url.trim_start_matches("self#jumbf=");
        let label = path.rsplit('/').next().unwrap_or(path);

        let Some(found) = assertions.and_then(|store| store.child(label)) else {
            status.failure.push(Status::new(
                "assertion.missing",
                format!("the claim references {label}, which is not in the assertion store"),
            ));
            continue;
        };

        checked += 1;
        if sha256(&found.contents_for_hash()) != expected {
            mismatched += 1;
            status.failure.push(Status::new(
                "assertion.hashedURI.mismatch",
                format!("{label} does not match the hash recorded in the claim"),
            ));
        }
    }

    if checked > 0 && mismatched == 0 {
        status.success.push(Status::new(
            "assertion.hashedURI.match",
            format!("all {checked} assertions match the hashes in the claim"),
        ));
    }
}

fn check_signature(
    manifest: &Superbox,
    claim_bytes: &[u8],
    report: &mut ManifestReport,
    status: &mut StatusCodes,
) {
    let Some(signature_box) = manifest
        .child(LABEL_SIGNATURE)
        .and_then(Superbox::cbor_payload)
    else {
        status.failure.push(Status::new(
            "claimSignature.missing",
            "the manifest has no claim signature",
        ));
        return;
    };

    let parsed = match cose::parse(signature_box) {
        Ok(parsed) => parsed,
        Err(e) => {
            status
                .failure
                .push(Status::new("claimSignature.mismatch", e.to_string()));
            return;
        }
    };

    report.signature.algorithm = parsed.algorithm_name().to_string();
    report.signature.time_stamped = false;

    if let Some(certificate) = parsed.chain.first() {
        if let Ok(certificate) = x509::parse_certificate(certificate) {
            report.signature.subject = certificate.subject.clone();
            report.signature.subject_organisation = certificate.subject_organisation.clone();
            report.signature.issuer = if certificate.issuer_common_name.is_empty() {
                certificate.issuer.clone()
            } else {
                certificate.issuer_common_name.clone()
            };
            report.signature.not_before = certificate.not_before.clone();
            report.signature.not_after = certificate.not_after.clone();
        }
    }

    match cose::verify(&parsed, claim_bytes) {
        Ok(()) => status.success.push(Status::new(
            "claimSignature.validated",
            "the claim matches its signature",
        )),
        Err(e) => status
            .failure
            .push(Status::new("claimSignature.mismatch", e.to_string())),
    }

    // Say plainly what has not been established. This validator has no trust
    // anchor store, so it cannot tell a real signer from an impostor, and
    // reporting the signature as simply "valid" would overstate the result.
    status.informational.push(Status::new(
        "signingCredential.untrusted",
        "the signer was not checked against any trust list",
    ));
}

/// Recompute the hard binding: hash the file with the manifest's own bytes
/// excluded and compare against what the assertion recorded.
fn check_hard_binding(
    jpeg: &[u8],
    manifest: &Superbox,
    embedded: &jpegxt::EmbeddedStore,
) -> StatusCodes {
    let mut status = StatusCodes::default();

    let Some(assertion) = manifest
        .child(LABEL_ASSERTIONS)
        .and_then(|store| store.child(LABEL_HASH_DATA))
        .and_then(Superbox::cbor_payload)
        .and_then(|bytes| super::cbor::decode(bytes).ok())
    else {
        // Not necessarily wrong: a box-hash or BMFF binding is legal too, and
        // this build only knows how to check data hashes.
        status.informational.push(Status::new(
            "assertion.dataHash.malformed",
            "no readable c2pa.hash.data assertion; the hard binding was not checked",
        ));
        return status;
    };

    let Some(expected) = assertion.get("hash").and_then(Value::as_bytes) else {
        status.failure.push(Status::new(
            "assertion.dataHash.malformed",
            "the data hash assertion has no hash",
        ));
        return status;
    };

    let exclusions: Vec<(usize, usize)> = assertion
        .get("exclusions")
        .and_then(Value::as_array)
        .map(|ranges| {
            ranges
                .iter()
                .filter_map(|range| {
                    Some((
                        range.get("start")?.as_u64()? as usize,
                        range.get("length")?.as_u64()? as usize,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    // Section 15.10.3: the excluded region must be the manifest store and
    // nothing else. Without this check an attacker could widen the exclusion to
    // cover real image data and hide a modification inside the gap.
    let covers_manifest = exclusions
        .iter()
        .any(|(start, length)| *start == embedded.start && *length == embedded.length);
    if !covers_manifest {
        status.failure.push(Status::new(
            "assertion.dataHash.mismatch",
            "the excluded range does not match where the manifest actually is",
        ));
        return status;
    }
    if exclusions.len() > 1 {
        status.informational.push(Status::new(
            "assertion.dataHash.additionalExclusionsPresent",
            "the hard binding excludes ranges beyond the manifest store",
        ));
    }

    let mut sorted = exclusions;
    sorted.sort_unstable();

    let mut hasher = Sha256::new();
    let mut at = 0usize;
    for (start, length) in sorted {
        if start < at || start > jpeg.len() {
            status.failure.push(Status::new(
                "assertion.dataHash.malformed",
                "exclusion ranges overlap or fall outside the file",
            ));
            return status;
        }
        hasher.update(&jpeg[at..start]);
        at = start.saturating_add(length).min(jpeg.len());
    }
    hasher.update(&jpeg[at..]);

    if hasher.finalize().to_vec() == expected {
        status.success.push(Status::new(
            "assertion.dataHash.match",
            "the image data matches the hash recorded when it was signed",
        ));
    } else {
        status.failure.push(Status::new(
            "assertion.dataHash.mismatch",
            "the image data has changed since it was signed",
        ));
    }

    status
}
