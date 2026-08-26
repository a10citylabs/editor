//! The conformance test harness.
//!
//! The C2PA Conformance Program requires any applicant whose product validates
//! manifests to run a harness over assets the Program supplies and hand back
//! the results in crJSON. From *Additional Conformance Requirements* v0.2, the
//! harness "SHALL accept the following inputs":
//!
//! 1. an asset to validate
//! 2. a (test) C2PA Trust List
//! 3. a (test) C2PA TSA Trust List
//! 4. a validation time (RFC 3339)
//!
//! Those are exactly the four flags below, and they map one-to-one onto
//! `imagecore::c2pa::ValidationOptions`. That matters more than the command
//! line does: this binary is a front end over the same validator the browser
//! runs, not a second implementation that could quietly disagree with it. If
//! the harness says a manifest is trusted, the editor says so too, because it
//! is the same function.
//!
//! ```text
//!   c2pa-harness validate \
//!       --asset signed.jpg \
//!       --trust-list c2pa-trust-list.pem \
//!       --tsa-trust-list c2pa-tsa-trust-list.pem \
//!       --validation-time 2026-03-10T12:34:56Z \
//!       --output signed.crjson
//! ```
//!
//! Exit status is 0 when the asset validated, 1 when it did not, and 2 when the
//! harness could not run at all. A validation failure is a result, not an
//! error: the Program's asset library is full of assets that are *meant* to
//! fail, and the crJSON says which check caught them.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use imagecore::c2pa::{self, clock, TrustStore, ValidationOptions};

const USAGE: &str = "\
c2pa-harness — validate a C2PA asset and report the result in crJSON

USAGE:
    c2pa-harness validate --asset <FILE> [options]
    c2pa-harness batch --asset-dir <DIR> --output-dir <DIR> [options]

OPTIONS:
    --asset <FILE>              the asset to validate
    --asset-dir <DIR>           (batch) every *.jpg / *.jpeg in this directory
    --trust-list <FILE>         PEM bundle of C2PA trust anchors
    --tsa-trust-list <FILE>     PEM bundle of TSA trust anchors
    --validation-time <RFC3339> the instant to judge certificate validity at
    --output <FILE>             write crJSON here instead of standard output
    --output-dir <DIR>          (batch) write one .crjson per asset here
    --summary                   also print a one-line human summary to stderr
    -h, --help                  show this text

EXIT STATUS:
    0  the asset validated
    1  the asset did not validate
    2  the harness could not run
";

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::from(0),
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("c2pa-harness: {message}");
            ExitCode::from(2)
        }
    }
}

#[derive(Default)]
struct Args {
    command: String,
    asset: Option<PathBuf>,
    asset_dir: Option<PathBuf>,
    trust_list: Option<PathBuf>,
    tsa_trust_list: Option<PathBuf>,
    validation_time: Option<String>,
    output: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    summary: bool,
}

fn run() -> Result<bool, String> {
    let args = parse_args()?;

    match args.command.as_str() {
        "validate" => validate_one(&args),
        "batch" => validate_batch(&args),
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

fn parse_args() -> Result<Args, String> {
    let mut raw = std::env::args().skip(1);
    let mut args = Args::default();

    let Some(command) = raw.next() else {
        return Err(format!("no command given\n\n{USAGE}"));
    };
    if command == "-h" || command == "--help" {
        println!("{USAGE}");
        std::process::exit(0);
    }
    args.command = command;

    while let Some(flag) = raw.next() {
        let mut value = || raw.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--asset" => args.asset = Some(PathBuf::from(value()?)),
            "--asset-dir" => args.asset_dir = Some(PathBuf::from(value()?)),
            "--trust-list" => args.trust_list = Some(PathBuf::from(value()?)),
            "--tsa-trust-list" => args.tsa_trust_list = Some(PathBuf::from(value()?)),
            "--validation-time" => args.validation_time = Some(value()?),
            "--output" => args.output = Some(PathBuf::from(value()?)),
            "--output-dir" => args.output_dir = Some(PathBuf::from(value()?)),
            "--summary" => args.summary = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
    }

    Ok(args)
}

/// Turn the four required inputs into the options the validator takes.
fn options_from(args: &Args) -> Result<ValidationOptions, String> {
    let load = |path: &Option<PathBuf>, what: &str| -> Result<TrustStore, String> {
        let Some(path) = path else {
            return Ok(TrustStore::empty());
        };
        let pem = std::fs::read_to_string(path)
            .map_err(|e| format!("reading the {what} at {}: {e}", path.display()))?;
        let (store, skipped) = TrustStore::from_pem(&pem)
            .map_err(|e| format!("parsing the {what} at {}: {e}", path.display()))?;
        if skipped > 0 {
            // Worth saying out loud: a trust list that half-loaded would
            // otherwise produce a mysteriously untrusted result.
            eprintln!(
                "c2pa-harness: {skipped} entr{} in the {what} could not be parsed and {} skipped",
                if skipped == 1 { "y" } else { "ies" },
                if skipped == 1 { "was" } else { "were" },
            );
        }
        Ok(store)
    };

    // The validation time is required in substance even though the flag is
    // optional: without one there is no defensible answer to "was this
    // certificate valid?". Defaulting to the epoch would make everything read
    // as not-yet-valid, so say so instead.
    let validation_time =
        match &args.validation_time {
            Some(text) => clock::parse_rfc3339(text)
                .ok_or_else(|| format!("'{text}' is not an RFC 3339 date-time"))?,
            None => return Err(
                "--validation-time is required; the Conformance Program supplies one with each \
                 test asset"
                    .into(),
            ),
        };

    Ok(ValidationOptions {
        trust: load(&args.trust_list, "trust list")?,
        tsa_trust: load(&args.tsa_trust_list, "TSA trust list")?,
        validation_time,
    })
}

fn validate_one(args: &Args) -> Result<bool, String> {
    let Some(asset) = &args.asset else {
        return Err(format!("validate needs --asset\n\n{USAGE}"));
    };
    let options = options_from(args)?;
    let (document, valid, summary) = validate_file(asset, &options)?;

    let rendered =
        serde_json::to_string_pretty(&document).map_err(|e| format!("serialising crJSON: {e}"))?;
    match &args.output {
        Some(path) => std::fs::write(path, format!("{rendered}\n"))
            .map_err(|e| format!("writing {}: {e}", path.display()))?,
        None => println!("{rendered}"),
    }
    if args.summary {
        eprintln!("{summary}");
    }

    Ok(valid)
}

fn validate_batch(args: &Args) -> Result<bool, String> {
    let Some(dir) = &args.asset_dir else {
        return Err(format!("batch needs --asset-dir\n\n{USAGE}"));
    };
    let Some(out_dir) = &args.output_dir else {
        return Err(format!("batch needs --output-dir\n\n{USAGE}"));
    };
    let options = options_from(args)?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("creating {}: {e}", out_dir.display()))?;

    let mut assets: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg"))
        })
        .collect();
    assets.sort();

    if assets.is_empty() {
        return Err(format!("no JPEG assets found in {}", dir.display()));
    }

    let mut all_valid = true;
    for asset in &assets {
        let stem = asset.file_stem().unwrap_or_default().to_string_lossy();
        match validate_file(asset, &options) {
            Ok((document, valid, summary)) => {
                all_valid &= valid;
                let path = out_dir.join(format!("{stem}.crjson"));
                let rendered = serde_json::to_string_pretty(&document)
                    .map_err(|e| format!("serialising crJSON for {stem}: {e}"))?;
                std::fs::write(&path, format!("{rendered}\n"))
                    .map_err(|e| format!("writing {}: {e}", path.display()))?;
                eprintln!("{summary}");
            }
            Err(why) => {
                // One unreadable asset should not abandon the batch: the
                // Program's library deliberately includes broken files.
                all_valid = false;
                eprintln!("{stem}: could not be validated — {why}");
            }
        }
    }

    Ok(all_valid)
}

fn validate_file(
    path: &Path,
    options: &ValidationOptions,
) -> Result<(serde_json::Value, bool, String), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    let Some(report) = c2pa::validate_jpeg(&bytes, options)? else {
        return Err("the asset carries no Content Credentials".into());
    };

    let failures = report.active.status.failure.len();
    let summary = format!(
        "{name}: {} — {} success, {} informational, {failures} failure{}{}",
        if report.is_valid() {
            "valid"
        } else {
            "INVALID"
        },
        report.active.status.success.len(),
        report.active.status.informational.len(),
        if failures == 1 { "" } else { "s" },
        if report.active.signature.trusted {
            format!(
                ", signer trusted via {}",
                report.active.signature.trust_anchor
            )
        } else {
            String::new()
        },
    );

    Ok((c2pa::to_crjson(&report), report.is_valid(), summary))
}
