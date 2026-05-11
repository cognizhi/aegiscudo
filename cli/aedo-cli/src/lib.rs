use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use aegiscudo_core::{PackageCoordinate, PackageEcosystem, PolicyDecision};
use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use jsonschema::JSONSchema;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

const DEFAULT_API_URL: &str = "http://127.0.0.1:8082";
const CONFIG_OVERRIDE_ENV: &str = "AEDO_CONFIG_HOME";
const HEALTH_TIMEOUT: Duration = Duration::from_millis(1_500);
const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "aedo",
    version,
    about = "Aegiscudo developer and CI preflight CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Scan {
        #[command(subcommand)]
        command: ScanCommand,
    },
    Explain(ExplainArgs),
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Ci {
        #[command(subcommand)]
        command: CiCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Login(AuthLoginArgs),
    Logout,
    Status,
}

#[derive(Debug, Args)]
struct AuthLoginArgs {
    #[arg(
        long,
        env = "AEGISCUDO_API_URL",
        default_value = DEFAULT_API_URL
    )]
    api_url: String,
    #[arg(long, env = "AEGISCUDO_TOKEN")]
    token: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ScanCommand {
    Npm(NpmScanArgs),
    Pnpm(PnpmScanArgs),
    Pypi(PypiScanArgs),
    Cargo(NotYetSupportedArgs),
    Maven(NotYetSupportedArgs),
    Docker(NotYetSupportedArgs),
}

#[derive(Debug, Args)]
struct NpmScanArgs {
    #[arg(long)]
    lockfile: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
    #[arg(long, default_value_t = false)]
    upload_manifest: bool,
}

#[derive(Debug, Args)]
struct PnpmScanArgs {
    #[arg(long)]
    lockfile: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
    #[arg(long, default_value_t = false)]
    upload_manifest: bool,
}

#[derive(Debug, Args)]
struct PypiScanArgs {
    #[arg(long)]
    requirements: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
    #[arg(long, default_value_t = false)]
    upload_manifest: bool,
}

#[derive(Debug, Args)]
struct NotYetSupportedArgs {}

#[derive(Debug, Args)]
struct ExplainArgs {
    package: String,
    #[arg(long, value_enum)]
    ecosystem: EcosystemArg,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Test(PolicyTestArgs),
}

#[derive(Debug, Args)]
struct PolicyTestArgs {
    #[arg(long)]
    file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum CiCommand {
    Preflight(CiPreflightArgs),
}

#[derive(Debug, Args)]
struct CiPreflightArgs {
    #[arg(long, value_enum, default_value_t = OutputFormat::Sarif)]
    format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EcosystemArg {
    Npm,
    Pypi,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum FailOn {
    Warn,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanFinding {
    coordinate: PackageCoordinate,
    #[serde(skip_serializing_if = "Option::is_none")]
    integrity: Option<String>,
    decision: PolicyDecision,
}

#[derive(Debug, Serialize)]
struct ScanReport {
    source: String,
    upload_manifest: bool,
    findings: Vec<ScanFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CliConfig {
    api_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct CliScanSubmission {
    packages: Vec<CliScanSubmissionPackage>,
}

#[derive(Debug, Serialize)]
struct CliScanSubmissionPackage {
    coordinate: PackageCoordinate,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CliScanApiResponse {
    findings: Vec<CliScanApiFinding>,
}

#[derive(Debug, Deserialize)]
struct CliScanApiFinding {
    coordinate: PackageCoordinate,
    decision: PolicyDecision,
}

#[derive(Debug, Serialize)]
struct CliExplainSubmission {
    coordinate: PackageCoordinate,
}

#[derive(Debug, Deserialize)]
struct CliExplainApiResponse {
    coordinate: PackageCoordinate,
    trace_id: String,
    recommended_action: String,
    confidence: String,
    summary: serde_json::Value,
    ai_explanation: Option<serde_json::Value>,
}

pub fn run(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<i32> {
    match Cli::parse_from(args).command {
        Command::Auth { command } => run_auth(command),
        Command::Scan { command } => run_scan(command),
        Command::Explain(args) => run_explain(args),
        Command::Policy { command } => match command {
            PolicyCommand::Test(args) => run_policy_test(args),
        },
        Command::Ci { command } => match command {
            CiCommand::Preflight(args) => run_ci_preflight(args),
        },
    }
}

fn run_policy_test(args: PolicyTestArgs) -> anyhow::Result<i32> {
    validate_policy_file(&args.file)?;
    println!(
        "policy file is schema-valid for dry-run submission: {}",
        args.file.display()
    );
    Ok(0)
}

fn validate_policy_file(path: &Path) -> anyhow::Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading policy file {}", path.display()))?;
    let policy: serde_json::Value = serde_yaml::from_str(&contents)
        .with_context(|| format!("parsing policy file {} as YAML or JSON", path.display()))?;

    if let Err(validation_errors) = policy_schema().validate(&policy) {
        let collected = validation_errors
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        anyhow::bail!(
            "policy file {} failed schema validation: {}",
            path.display(),
            collected.join("; ")
        );
    }

    Ok(())
}

fn policy_schema() -> &'static JSONSchema {
    static POLICY_SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
    POLICY_SCHEMA.get_or_init(|| {
        let schema_json: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/policy.schema.json"
        ))
        .expect("policy schema should parse");
        JSONSchema::compile(&schema_json).expect("policy schema should compile")
    })
}

fn run_ci_preflight(args: CiPreflightArgs) -> anyhow::Result<i32> {
    let cwd = env::current_dir().context("reading current working directory for ci preflight")?;
    let discovered = discover_ci_preflight_inputs(&cwd)?;
    let source = format!(
        "ci-preflight: {}",
        discovered
            .iter()
            .map(|(source, _)| source.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let findings = aggregate_ci_preflight_findings(discovered)?;
    let report = submit_scan_report(source, false, findings)?;
    print_report(&report, args.format)?;
    Ok(exit_code(&report.findings, args.fail_on))
}

fn discover_ci_preflight_inputs(cwd: &Path) -> anyhow::Result<Vec<(String, Vec<ScanFinding>)>> {
    let supported_files = [
        ("package-lock.json", parse_package_lock as fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>),
        ("pnpm-lock.yaml", parse_pnpm_lock as fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>),
        ("requirements.txt", parse_requirements as fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>),
        (
            "requirements-dev.txt",
            parse_requirements as fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>,
        ),
    ];
    let mut discovered = Vec::new();

    for (file_name, parser) in supported_files {
        let path = cwd.join(file_name);
        if !path.exists() {
            continue;
        }
        discovered.push((file_name.to_owned(), parser(&path)?));
    }

    if discovered.is_empty() {
        let yarn_lock = cwd.join("yarn.lock");
        if yarn_lock.exists() {
            anyhow::bail!(
                "ci preflight currently supports package-lock.json, pnpm-lock.yaml, requirements.txt, and requirements-dev.txt in the current directory; yarn.lock is not yet supported"
            );
        }

        anyhow::bail!(
            "ci preflight found no supported dependency files in {}; supported files: package-lock.json, pnpm-lock.yaml, requirements.txt, requirements-dev.txt",
            cwd.display()
        );
    }

    Ok(discovered)
}

fn aggregate_ci_preflight_findings(
    discovered: Vec<(String, Vec<ScanFinding>)>,
) -> anyhow::Result<Vec<ScanFinding>> {
    let mut merged: BTreeMap<String, (ScanFinding, String)> = BTreeMap::new();

    for (source, findings) in discovered {
        for finding in findings {
            let key = finding.coordinate.purl();
            if let Some((existing, existing_source)) = merged.get_mut(&key) {
                match (existing.integrity.as_deref(), finding.integrity.as_deref()) {
                    (Some(current), Some(candidate)) if current != candidate => {
                        anyhow::bail!(
                            "ci preflight found conflicting integrity values for {} in {} and {}",
                            key,
                            existing_source,
                            source
                        );
                    }
                    (None, Some(_)) => existing.integrity = finding.integrity.clone(),
                    _ => {}
                }
                continue;
            }

            merged.insert(key, (finding, source.clone()));
        }
    }

    Ok(merged
        .into_values()
        .map(|(finding, _)| finding)
        .collect::<Vec<_>>())
}

fn run_auth(command: AuthCommand) -> anyhow::Result<i32> {
    match command {
        AuthCommand::Login(args) => {
            let existing = load_cli_config()?;
            let config = CliConfig {
                api_url: normalize_api_url(&args.api_url),
                token: args.token.or(existing.and_then(|entry| entry.token)),
            };
            probe_api_health(&config.api_url)?;
            let config_path = save_cli_config(&config)?;
            let token_status = if config.token.is_some() {
                "token configured"
            } else {
                "token not configured"
            };
            println!(
                "saved CLI config at {} for {} ({token_status})",
                config_path.display(),
                config.api_url,
            );
        }
        AuthCommand::Logout => {
            let config_path = cli_config_path()?;
            if clear_cli_config()? {
                println!("local auth state cleared at {}", config_path.display());
            } else {
                println!("local auth state already empty at {}", config_path.display());
            }
        }
        AuthCommand::Status => match load_cli_config()? {
            Some(config) => {
                let health = if probe_api_health(&config.api_url).is_ok() {
                    "reachable"
                } else {
                    "unreachable"
                };
                let token_status = if config.token.is_some() {
                    "configured"
                } else {
                    "not configured"
                };
                println!(
                    "auth status: configured for {} (token: {token_status}, api: {health})",
                    config.api_url,
                );
            }
            None => println!("auth status: not configured"),
        },
    }
    Ok(0)
}

fn cli_config_path() -> anyhow::Result<PathBuf> {
    let base_dir = if let Ok(path) = env::var(CONFIG_OVERRIDE_ENV) {
        PathBuf::from(path)
    } else if let Ok(path) = env::var("XDG_CONFIG_HOME") {
        PathBuf::from(path).join("aegiscudo")
    } else if let Ok(path) = env::var("HOME") {
        PathBuf::from(path).join(".config").join("aegiscudo")
    } else {
        anyhow::bail!(
            "HOME or XDG_CONFIG_HOME must be set to persist CLI configuration"
        );
    };

    Ok(base_dir.join("aedo.json"))
}

fn load_cli_config() -> anyhow::Result<Option<CliConfig>> {
    let path = cli_config_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&path)
        .with_context(|| format!("reading CLI config {}", path.display()))?;
    let config = serde_json::from_str(&contents)
        .with_context(|| format!("parsing CLI config {}", path.display()))?;
    Ok(Some(config))
}

fn save_cli_config(config: &CliConfig) -> anyhow::Result<PathBuf> {
    let path = cli_config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating CLI config directory {}", parent.display()))?;
    }
    fs::write(&path, serde_json::to_vec_pretty(config)?)
        .with_context(|| format!("writing CLI config {}", path.display()))?;
    Ok(path)
}

fn clear_cli_config() -> anyhow::Result<bool> {
    let path = cli_config_path()?;
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(&path)
        .with_context(|| format!("removing CLI config {}", path.display()))?;
    Ok(true)
}

fn normalize_api_url(api_url: &str) -> String {
    api_url.trim_end_matches('/').to_owned()
}

fn probe_api_health(api_url: &str) -> anyhow::Result<()> {
    let client = Client::builder().timeout(HEALTH_TIMEOUT).build()?;
    client
        .get(format!("{}/healthz", normalize_api_url(api_url)))
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("probing Aegiscudo API health at {api_url}/healthz"))?;
    Ok(())
}

fn run_scan(command: ScanCommand) -> anyhow::Result<i32> {
    match command {
        ScanCommand::Npm(args) => {
            ensure_manifest_upload_supported(args.upload_manifest)?;
            let findings = parse_package_lock(&args.lockfile)?;
            let report = submit_scan_report(
                args.lockfile.display().to_string(),
                args.upload_manifest,
                findings,
            )?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Pnpm(args) => {
            ensure_manifest_upload_supported(args.upload_manifest)?;
            let findings = parse_pnpm_lock(&args.lockfile)?;
            let report = submit_scan_report(
                args.lockfile.display().to_string(),
                args.upload_manifest,
                findings,
            )?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Pypi(args) => {
            ensure_manifest_upload_supported(args.upload_manifest)?;
            let findings = parse_requirements(&args.requirements)?;
            let report = submit_scan_report(
                args.requirements.display().to_string(),
                args.upload_manifest,
                findings,
            )?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Cargo(_) | ScanCommand::Maven(_) | ScanCommand::Docker(_) => {
            println!("not-yet-supported: this ecosystem is phase-gated after the npm/PyPI MVP");
            Ok(3)
        }
    }
}

fn ensure_manifest_upload_supported(upload_manifest: bool) -> anyhow::Result<()> {
    if upload_manifest {
        anyhow::bail!(
            "--upload-manifest is not yet supported in Phase 1; aedo currently submits package coordinates and artifact digests only"
        );
    }

    Ok(())
}

fn run_explain(args: ExplainArgs) -> anyhow::Result<i32> {
    let config = load_api_config()?;
    let coordinate = parse_explain_coordinate(&args.package, args.ecosystem)?;
    let response = submit_explain_request(&config, &coordinate)?;

    println!("coordinate: {}", response.coordinate.purl());
    println!("decision: {}", response.recommended_action);
    println!("confidence: {}", response.confidence);
    println!("trace_id: {}", response.trace_id);
    println!("summary:");
    println!("{}", serde_json::to_string_pretty(&response.summary)?);
    if let Some(ai_explanation) = response.ai_explanation {
        println!("ai_explanation:");
        println!("{}", serde_json::to_string_pretty(&ai_explanation)?);
    }

    Ok(0)
}

fn parse_pnpm_lock(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut findings = Vec::new();
    let mut in_packages = false;
    let mut current_key: Option<String> = None;

    for line in contents.lines() {
        // Top-level YAML section header (no leading whitespace)
        if !line.starts_with(' ') {
            if !line.is_empty() {
                in_packages = line == "packages:";
                current_key = None;
            }
            continue;
        }

        if !in_packages {
            continue;
        }

        // 2-space-indented package key: "  'name@version':" or "  name@version:"
        if let Some(rest) = line.strip_prefix("  ") {
            if !rest.starts_with(' ') && rest.ends_with(':') {
                let key = rest.trim_end_matches(':').trim_matches('\'');
                current_key = Some(key.to_owned());
                continue;
            }
        }

        // 4-space-indented resolution line: "    resolution: {integrity: sha512-...}"
        if current_key.is_some() {
            if let Some(rest) = line.strip_prefix("    resolution: {integrity: ") {
                let integrity = rest
                    .split_once([',', '}'])
                    .map(|(v, _)| v)
                    .unwrap_or_else(|| rest.trim_end_matches('}'));
                let key = current_key.take().unwrap();
                let (name, version) = split_pnpm_key(&key);
                if !name.is_empty() && !version.is_empty() {
                    findings.push(finding(
                        PackageEcosystem::Npm,
                        name,
                        Some(version),
                        Some(integrity.to_owned()),
                    ));
                }
            }
        }
    }

    Ok(findings)
}

/// Split a pnpm lockfile package key into (name, version).
/// Keys follow the format `name@version` for unscoped packages and
/// `@scope/name@version` for scoped packages.
fn split_pnpm_key(key: &str) -> (String, String) {
    if key.starts_with('@') {
        // Scoped: find the '@' that comes after the first '/'
        if let Some(slash) = key.find('/') {
            if let Some(at) = key[slash + 1..].find('@') {
                let sep = slash + 1 + at;
                return (key[..sep].to_owned(), key[sep + 1..].to_owned());
            }
        }
    } else if let Some(at) = key.find('@') {
        return (key[..at].to_owned(), key[at + 1..].to_owned());
    }
    (key.to_owned(), String::new())
}

fn parse_package_lock(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
        match file_name {
            "yarn.lock" => anyhow::bail!(
                "npm scan currently supports package-lock.json only; yarn.lock is not yet supported"
            ),
            "pnpm-lock.yaml" => anyhow::bail!(
                "npm scan currently supports package-lock.json only; use `aedo scan pnpm --lockfile pnpm-lock.yaml` for pnpm lockfiles"
            ),
            _ => {}
        }
    }

    #[derive(Deserialize)]
    struct PackageLock {
        #[serde(default)]
        packages: BTreeMap<String, PackageEntry>,
        #[serde(default)]
        dependencies: BTreeMap<String, PackageEntry>,
    }
    #[derive(Deserialize)]
    struct PackageEntry {
        version: Option<String>,
        integrity: Option<String>,
    }

    let lockfile: PackageLock = serde_json::from_str(
        &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing npm lockfile {}", path.display()))?;

    let mut findings = Vec::new();
    for (package_path, entry) in lockfile.packages {
        if package_path.is_empty() || !package_path.starts_with("node_modules/") {
            continue;
        }
        let name = package_path.trim_start_matches("node_modules/").to_owned();
        findings.push(finding(
            PackageEcosystem::Npm,
            name,
            entry.version,
            entry.integrity,
        ));
    }
    if findings.is_empty() {
        for (name, entry) in lockfile.dependencies {
            findings.push(finding(
                PackageEcosystem::Npm,
                name,
                entry.version,
                entry.integrity,
            ));
        }
    }
    Ok(findings)
}

fn parse_requirements(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut findings = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        let package = trimmed.split('#').next().unwrap_or(trimmed).trim();
        let (name, version) = package
            .split_once("==")
            .map(|(name, version)| (name.trim().to_owned(), Some(version.trim().to_owned())))
            .unwrap_or_else(|| {
                (
                    package
                        .split(['<', '>', '~', '='])
                        .next()
                        .unwrap_or(package)
                        .trim()
                        .to_owned(),
                    None,
                )
            });
        findings.push(finding(PackageEcosystem::Pypi, name, version, None));
    }
    Ok(findings)
}

fn finding(
    ecosystem: PackageEcosystem,
    raw_name: String,
    version: Option<String>,
    integrity: Option<String>,
) -> ScanFinding {
    let (namespace, name) = if ecosystem == PackageEcosystem::Npm && raw_name.starts_with('@') {
        match raw_name.split_once('/') {
            Some((scope, name)) => (
                Some(scope.trim_start_matches('@').to_owned()),
                name.to_owned(),
            ),
            None => (None, raw_name),
        }
    } else {
        (None, raw_name)
    };
    ScanFinding {
        coordinate: PackageCoordinate::new(ecosystem, name, version, namespace),
        integrity,
        decision: PolicyDecision::Allow,
    }
}

fn submit_scan_report(
    source: String,
    upload_manifest: bool,
    findings: Vec<ScanFinding>,
) -> anyhow::Result<ScanReport> {
    if findings.is_empty() {
        return Ok(ScanReport {
            source,
            upload_manifest,
            findings,
        });
    }

    let config = load_api_config()?;
    let remote_findings = submit_scan_findings(&config, &findings)?;
    Ok(ScanReport {
        source,
        upload_manifest,
        findings: merge_scan_findings(findings, remote_findings)?,
    })
}

fn load_api_config() -> anyhow::Result<CliConfig> {
    Ok(load_cli_config()?.unwrap_or_else(|| CliConfig {
        api_url: normalize_api_url(DEFAULT_API_URL),
        token: None,
    }))
}

fn submit_scan_findings(
    config: &CliConfig,
    findings: &[ScanFinding],
) -> anyhow::Result<Vec<CliScanApiFinding>> {
    let client = Client::builder().timeout(SCAN_TIMEOUT).build()?;
    let submission = CliScanSubmission {
        packages: findings
            .iter()
            .map(|finding| CliScanSubmissionPackage {
                coordinate: finding.coordinate.clone(),
                artifact_sha256: artifact_sha256_from_finding(finding),
            })
            .collect(),
    };

    let mut request = client
        .post(format!("{}/v1/cli/scans", config.api_url))
        .json(&submission);
    if let Some(token) = config.token.as_deref() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("submitting CLI scan to {}/v1/cli/scans", config.api_url))?;
    let body: CliScanApiResponse = response
        .json()
        .with_context(|| format!("parsing CLI scan response from {}", config.api_url))?;
    Ok(body.findings)
}

fn submit_explain_request(
    config: &CliConfig,
    coordinate: &PackageCoordinate,
) -> anyhow::Result<CliExplainApiResponse> {
    let client = Client::builder().timeout(SCAN_TIMEOUT).build()?;
    let mut request = client
        .post(format!("{}/v1/cli/explain", config.api_url))
        .json(&CliExplainSubmission {
            coordinate: coordinate.clone(),
        });
    if let Some(token) = config.token.as_deref() {
        request = request.bearer_auth(token);
    }

    request
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("submitting explain lookup to {}/v1/cli/explain", config.api_url))?
        .json()
        .with_context(|| format!("parsing explain response from {}", config.api_url))
}

fn parse_explain_coordinate(
    spec: &str,
    ecosystem: EcosystemArg,
) -> anyhow::Result<PackageCoordinate> {
    match ecosystem {
        EcosystemArg::Npm => parse_npm_explain_coordinate(spec),
        EcosystemArg::Pypi => parse_pypi_explain_coordinate(spec),
    }
}

fn parse_npm_explain_coordinate(spec: &str) -> anyhow::Result<PackageCoordinate> {
    let trimmed = spec.trim();
    let separator = trimmed
        .rfind('@')
        .filter(|index| *index > 0)
        .ok_or_else(|| anyhow::anyhow!("npm explain expects <package>@<version>"))?;
    let name = &trimmed[..separator];
    let version = &trimmed[separator + 1..];
    if name.is_empty() || version.trim().is_empty() {
        anyhow::bail!("npm explain expects <package>@<version>");
    }

    if let Some(scoped_name) = name.strip_prefix('@') {
        let (scope, package_name) = scoped_name
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("scoped npm packages must be formatted as @scope/name@version"))?;
        if scope.is_empty() || package_name.is_empty() || package_name.contains('/') {
            anyhow::bail!("scoped npm packages must be formatted as @scope/name@version");
        }
        Ok(PackageCoordinate::new(
            PackageEcosystem::Npm,
            package_name,
            Some(version),
            Some(scope),
        ))
    } else {
        if name.contains('/') {
            anyhow::bail!("unscoped npm packages must be formatted as name@version");
        }
        Ok(PackageCoordinate::new(
            PackageEcosystem::Npm,
            name,
            Some(version),
            None::<String>,
        ))
    }
}

fn parse_pypi_explain_coordinate(spec: &str) -> anyhow::Result<PackageCoordinate> {
    let trimmed = spec.trim();
    let (name, version) = trimmed
        .rsplit_once('@')
        .ok_or_else(|| anyhow::anyhow!("pypi explain expects <package>@<version>"))?;
    if name.trim().is_empty() || version.trim().is_empty() {
        anyhow::bail!("pypi explain expects <package>@<version>");
    }
    Ok(PackageCoordinate::new(
        PackageEcosystem::Pypi,
        name.trim(),
        Some(version.trim()),
        None::<String>,
    ))
}

fn artifact_sha256_from_finding(finding: &ScanFinding) -> Option<String> {
    let raw = finding.integrity.as_deref()?.trim();
    let candidate = raw
        .strip_prefix("sha256-")
        .or_else(|| raw.strip_prefix("sha256:"))
        .unwrap_or(raw);
    if candidate.len() == 64 && candidate.chars().all(|character| character.is_ascii_hexdigit()) {
        Some(candidate.to_ascii_lowercase())
    } else {
        None
    }
}

fn merge_scan_findings(
    mut local_findings: Vec<ScanFinding>,
    remote_findings: Vec<CliScanApiFinding>,
) -> anyhow::Result<Vec<ScanFinding>> {
    if local_findings.len() != remote_findings.len() {
        anyhow::bail!(
            "scan response count {} did not match request count {}",
            remote_findings.len(),
            local_findings.len()
        );
    }

    for (local, remote) in local_findings.iter_mut().zip(remote_findings.into_iter()) {
        if local.coordinate != remote.coordinate {
            anyhow::bail!(
                "scan response did not align with request order for {}",
                local.coordinate.purl()
            );
        }
        local.decision = remote.decision;
    }

    Ok(local_findings)
}

fn print_report(report: &ScanReport, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Text => {
            for finding in &report.findings {
                println!(
                    "{} {}",
                    finding.coordinate.purl(),
                    serde_json::to_string(&finding.decision)?
                );
            }
            if report.findings.is_empty() {
                println!("no package coordinates found");
            }
        }
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Sarif => println!("{}", serde_json::to_string_pretty(&sarif(report))?),
    }
    Ok(())
}

fn sarif(report: &ScanReport) -> serde_json::Value {
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": { "name": "aedo-cli", "informationUri": "https://example.invalid/aegiscudo" } },
            "results": report.findings.iter().map(|finding| serde_json::json!({
                "ruleId": "aegiscudo-policy-decision",
                "level": match finding.decision { PolicyDecision::Allow => "note", PolicyDecision::AllowWithWarning => "warning", _ => "error" },
                "message": { "text": format!("{} -> {:?}", finding.coordinate.purl(), finding.decision) }
            })).collect::<Vec<_>>()
        }]
    })
}

fn exit_code(findings: &[ScanFinding], fail_on: FailOn) -> i32 {
    let failed = findings.iter().any(|finding| match fail_on {
        FailOn::Warn => finding.decision != PolicyDecision::Allow,
        FailOn::Block => finding.decision.is_blocking(),
    });
    if failed { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;
    use tempfile::tempdir;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn parses_package_lock_without_uploading_source() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        fs::write(&path, r#"{"packages":{"node_modules/@scope/pkg":{"version":"1.0.0","integrity":"sha512-x"}}}"#).unwrap();
        let findings = parse_package_lock(&path).unwrap();
        assert_eq!(findings[0].coordinate.purl(), "pkg:npm/scope/pkg@1.0.0");
        assert_eq!(findings[0].integrity.as_deref(), Some("sha512-x"));
    }

    #[test]
    fn parses_pnpm_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &path,
            "lockfileVersion: '9.0'\n\npackages:\n\n  ajv@8.20.0:\n    resolution: {integrity: sha512-abc==}\n    engines: {node: '>=12.0.0'}\n\n  '@babel/core@7.29.0':\n    resolution: {integrity: sha512-xyz==}\n    engines: {node: '>=6.9.0'}\n\nsnapshots:\n",
        )
        .unwrap();
        let findings = parse_pnpm_lock(&path).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].coordinate.purl(), "pkg:npm/ajv@8.20.0");
        assert_eq!(findings[0].integrity.as_deref(), Some("sha512-abc=="));
        assert_eq!(findings[1].coordinate.purl(), "pkg:npm/babel/core@7.29.0");
        assert_eq!(findings[1].integrity.as_deref(), Some("sha512-xyz=="));
    }

    #[test]
    fn split_pnpm_key_unscoped() {
        assert_eq!(
            split_pnpm_key("ajv@8.20.0"),
            ("ajv".to_owned(), "8.20.0".to_owned())
        );
    }

    #[test]
    fn split_pnpm_key_scoped() {
        assert_eq!(
            split_pnpm_key("@babel/core@7.29.0"),
            ("@babel/core".to_owned(), "7.29.0".to_owned())
        );
    }

    #[test]
    fn parses_requirements() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(&path, "requests==2.32.0\n# comment\nuvicorn>=0.30\n").unwrap();
        let findings = parse_requirements(&path).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/requests@2.32.0");
    }

    #[test]
    fn npm_scan_reports_clear_error_for_yarn_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("yarn.lock");
        fs::write(&path, "# yarn lockfile v1\nleft-pad@1.3.0:\n  version \"1.3.0\"\n").unwrap();

        let error = parse_package_lock(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("yarn.lock is not yet supported")
        );
    }

    #[test]
    fn npm_scan_reports_clear_error_for_pnpm_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pnpm-lock.yaml");
        fs::write(&path, "lockfileVersion: '9.0'\npackages:\n").unwrap();

        let error = parse_package_lock(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("use `aedo scan pnpm --lockfile pnpm-lock.yaml`")
        );
    }

    #[test]
    fn sarif_output_uses_expected_levels() {
        let report = ScanReport {
            source: "fixture-lockfile".to_owned(),
            upload_manifest: false,
            findings: vec![
                finding(
                    PackageEcosystem::Npm,
                    "safe-package".to_owned(),
                    Some("1.0.0".to_owned()),
                    None::<String>,
                ),
                ScanFinding {
                    coordinate: PackageCoordinate::new(
                        PackageEcosystem::Pypi,
                        "warn-package".to_owned(),
                        Some("2.0.0".to_owned()),
                        None::<String>,
                    ),
                    integrity: None::<String>,
                    decision: PolicyDecision::AllowWithWarning,
                },
                ScanFinding {
                    coordinate: PackageCoordinate::new(
                        PackageEcosystem::Pypi,
                        "blocked-package".to_owned(),
                        Some("3.0.0".to_owned()),
                        None::<String>,
                    ),
                    integrity: None::<String>,
                    decision: PolicyDecision::BlockPolicyViolation,
                },
            ],
        };

        let sarif = sarif(&report);
        let results = sarif["runs"][0]["results"].as_array().unwrap();

        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["level"], "note");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "error");
    }

    #[test]
    fn exit_code_respects_warn_and_block_thresholds() {
        let allow = finding(
            PackageEcosystem::Npm,
            "safe-package".to_owned(),
            Some("1.0.0".to_owned()),
            None::<String>,
        );
        let warning = ScanFinding {
            coordinate: PackageCoordinate::new(
                PackageEcosystem::Pypi,
                "warn-package".to_owned(),
                Some("2.0.0".to_owned()),
                None::<String>,
            ),
            integrity: None::<String>,
            decision: PolicyDecision::AllowWithWarning,
        };
        let block = ScanFinding {
            coordinate: PackageCoordinate::new(
                PackageEcosystem::Pypi,
                "blocked-package".to_owned(),
                Some("3.0.0".to_owned()),
                None::<String>,
            ),
            integrity: None::<String>,
            decision: PolicyDecision::BlockPolicyViolation,
        };

        assert_eq!(exit_code(&[allow.clone()], FailOn::Warn), 0);
        assert_eq!(exit_code(&[warning.clone()], FailOn::Block), 0);
        assert_eq!(exit_code(&[warning, allow], FailOn::Warn), 1);
        assert_eq!(exit_code(&[block], FailOn::Block), 1);
    }

    #[test]
    fn phase_gated_scan_targets_return_not_yet_supported_exit_code() {
        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("cargo"),
        ])
        .unwrap();

        assert_eq!(exit_code, 3);
    }

    #[test]
    fn scan_rejects_upload_manifest_until_supported() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("package-lock.json");
        fs::write(
            &lockfile,
            r#"{"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"sha512-x"}}}"#,
        )
        .unwrap();

        let error = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("npm"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--upload-manifest"),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("--upload-manifest is not yet supported"));
    }

    #[test]
    fn cli_config_round_trips_through_override_directory() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let config = CliConfig {
            api_url: "http://127.0.0.1:18002".to_owned(),
            token: Some("fixture-token".to_owned()),
        };
        let path = save_cli_config(&config).unwrap();
        assert!(path.exists());
        assert_eq!(load_cli_config().unwrap(), Some(config));
        assert!(clear_cli_config().unwrap());
        assert_eq!(load_cli_config().unwrap(), None);

        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    fn auth_login_persists_config_after_health_probe() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
            }
        });

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("auth"),
            OsString::from("login"),
            OsString::from("--api-url"),
            OsString::from(format!("http://{address}")),
            OsString::from("--token"),
            OsString::from("fixture-token"),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
        assert_eq!(
            load_cli_config().unwrap(),
            Some(CliConfig {
                api_url: format!("http://{address}"),
                token: Some("fixture-token".to_owned()),
            })
        );

        server.join().unwrap();
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    fn policy_test_accepts_schema_valid_yaml() {
        let dir = tempdir().unwrap();
        let policy_file = dir.path().join("aegiscudo-policy.yaml");
        fs::write(
            &policy_file,
            "id: 00000000-0000-0000-0000-000000000101\ntenant_id: 00000000-0000-0000-0000-000000000001\nversion: 2026.05.0\nmode: enforce\nminimum_release_age_hours: 24\nknown_vulnerability_threshold:\n  severity_floor: high\n  kev_override: true\n  epss_probability_floor: 0.7\nfail_closed: true\nrules:\n  - id: known-vulnerable\n    signal: vulnerable_above_threshold\n    action: warn\n    enabled: true\n",
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("policy"),
            OsString::from("test"),
            OsString::from("--file"),
            policy_file.into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn policy_test_rejects_schema_invalid_yaml() {
        let dir = tempdir().unwrap();
        let policy_file = dir.path().join("aegiscudo-policy.yaml");
        fs::write(
            &policy_file,
            "tenant_id: 00000000-0000-0000-0000-000000000001\nversion: 2026.05.0\nmode: enforce\nminimum_release_age_hours: 24\nknown_vulnerability_threshold:\n  severity_floor: high\n  kev_override: true\nfail_closed: true\nrules: []\n",
        )
        .unwrap();

        let error = run([
            OsString::from("aedo"),
            OsString::from("policy"),
            OsString::from("test"),
            OsString::from("--file"),
            policy_file.into_os_string(),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("failed schema validation"));
    }

    #[test]
    fn npm_scan_uses_remote_decisions_from_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let lockfile = dir.path().join("package-lock.json");
        fs::write(
            &lockfile,
            r#"{"packages":{"node_modules/@scope/pkg":{"version":"1.0.0","integrity":"sha512-x"}}}"#,
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/scans HTTP/1.1"));
                assert!(request.contains("\"name\":\"pkg\""));
                assert!(request.contains("\"namespace\":\"scope\""));
                assert!(request.contains("authorization: Bearer fixture-token"));

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "registry_config_id": "018f4a6f-55d0-7000-8000-000000000301",
                    "policy_profile_id": "018f4a6f-55d0-7000-8000-000000000101",
                    "findings": [{
                        "coordinate": {
                            "ecosystem": "npm",
                            "name": "pkg",
                            "version": "1.0.0",
                            "namespace": "scope"
                        },
                        "decision": "BLOCK_POLICY_VIOLATION",
                        "trace_id": "cli-trace-1",
                        "rationale": ["fixture block"],
                        "create_analysis_job": false
                    }]
                });
                let body = serde_json::to_vec(&response).unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("npm"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();

        assert_eq!(exit_code, 1);

        server.join().unwrap();
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    fn explain_parses_scoped_npm_coordinate() {
        let coordinate = parse_explain_coordinate("@scope/pkg@1.2.3", EcosystemArg::Npm).unwrap();

        assert_eq!(coordinate.purl(), "pkg:npm/scope/pkg@1.2.3");
    }

    #[test]
    fn explain_rejects_missing_version() {
        let error = parse_explain_coordinate("left-pad", EcosystemArg::Npm).unwrap_err();

        assert!(error.to_string().contains("expects <package>@<version>"));
    }

    #[test]
    fn explain_uses_remote_summary_from_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/explain HTTP/1.1"));
                assert!(request.contains("\"name\":\"pkg\""));
                assert!(request.contains("\"namespace\":\"scope\""));
                assert!(request.contains("authorization: Bearer fixture-token"));

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "analysis_job_id": "018f4a6f-55d0-7000-8000-000000000501",
                    "artifact_id": "018f4a6f-55d0-7000-8000-000000000601",
                    "trace_id": "trace-explain-1",
                    "coordinate": {
                        "ecosystem": "npm",
                        "name": "pkg",
                        "version": "1.2.3",
                        "namespace": "scope"
                    },
                    "artifact_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "recommended_action": "QUARANTINE_PENDING_ANALYSIS",
                    "confidence": "medium",
                    "summary": {"limitations": ["fixture limitation"]},
                    "ai_explanation": {"inference": ["fixture inference"]},
                    "created_at": "2026-05-10T10:00:00Z"
                });
                let body = serde_json::to_vec(&response).unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("explain"),
            OsString::from("@scope/pkg@1.2.3"),
            OsString::from("--ecosystem"),
            OsString::from("npm"),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        server.join().unwrap();
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    fn ci_preflight_discovers_package_lock_in_current_dir() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let lockfile = dir.path().join("package-lock.json");
        fs::write(
            &lockfile,
            r#"{"packages":{"node_modules/@scope/pkg":{"version":"1.0.0","integrity":"sha512-x"}}}"#,
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/scans HTTP/1.1"));
                assert!(request.contains("\"name\":\"pkg\""));
                assert!(request.contains("\"namespace\":\"scope\""));

                let response = serde_json::json!({
                    "findings": [{
                        "coordinate": {
                            "ecosystem": "npm",
                            "name": "pkg",
                            "version": "1.0.0",
                            "namespace": "scope"
                        },
                        "decision": "ALLOW"
                    }]
                });
                let body = serde_json::to_vec(&response).unwrap();
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        env::set_current_dir(dir.path()).unwrap();
        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("ci"),
            OsString::from("preflight"),
            OsString::from("--format"),
            OsString::from("json"),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();

        env::set_current_dir(original_dir).unwrap();
        assert_eq!(exit_code, 0);

        server.join().unwrap();
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    fn ci_preflight_aggregates_supported_files_across_ecosystems() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"sha512-x"}}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            "requests==2.32.0\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("requirements-dev.txt"),
            "pytest==8.3.3\n",
        )
        .unwrap();

        let aggregated = aggregate_ci_preflight_findings(discover_ci_preflight_inputs(dir.path()).unwrap()).unwrap();

        assert_eq!(
            aggregated
                .iter()
                .map(|finding| finding.coordinate.purl())
                .collect::<Vec<_>>(),
            vec![
                "pkg:npm/left-pad@1.3.0".to_owned(),
                "pkg:pypi/pytest@8.3.3".to_owned(),
                "pkg:pypi/requests@2.32.0".to_owned(),
            ]
        );
    }

    #[test]
    fn ci_preflight_rejects_conflicting_duplicate_integrity() {
        let error = aggregate_ci_preflight_findings(vec![
            (
                "package-lock.json".to_owned(),
                vec![finding(
                    PackageEcosystem::Npm,
                    "left-pad".to_owned(),
                    Some("1.3.0".to_owned()),
                    Some("sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
                )],
            ),
            (
                "pnpm-lock.yaml".to_owned(),
                vec![finding(
                    PackageEcosystem::Npm,
                    "left-pad".to_owned(),
                    Some("1.3.0".to_owned()),
                    Some("sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()),
                )],
            ),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("conflicting integrity values"));
    }

    #[test]
    fn ci_preflight_reports_missing_supported_files() {
        let dir = tempdir().unwrap();

        let error = discover_ci_preflight_inputs(dir.path()).unwrap_err();

        assert!(error.to_string().contains("found no supported dependency files"));
    }

    #[test]
    fn ci_preflight_reports_yarn_lock_as_unsupported() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("yarn.lock"), "# yarn lockfile v1\n").unwrap();

        let error = discover_ci_preflight_inputs(dir.path()).unwrap_err();

        assert!(error.to_string().contains("yarn.lock is not yet supported"));
    }

    #[test]
    fn ci_preflight_discovers_current_directory_only() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("requirements.txt"),
            "requests==2.32.0\n",
        )
        .unwrap();

        let error = discover_ci_preflight_inputs(dir.path()).unwrap_err();

        assert!(error.to_string().contains("found no supported dependency files"));
    }

    #[test]
    fn merge_scan_findings_rejects_misaligned_response_order() {
        let error = merge_scan_findings(
            vec![finding(
                PackageEcosystem::Npm,
                "left-pad".to_owned(),
                Some("1.3.0".to_owned()),
                None::<String>,
            )],
            vec![CliScanApiFinding {
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Npm,
                    "different-package",
                    Some("1.3.0"),
                    None::<String>,
                ),
                decision: PolicyDecision::AllowWithWarning,
            }],
        )
        .unwrap_err();

        assert!(error.to_string().contains("did not align with request order"));
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api process"]
    fn auth_login_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("auth"),
            OsString::from("login"),
            OsString::from("--api-url"),
            OsString::from(api_url.clone()),
            OsString::from("--token"),
            OsString::from("fixture-token"),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
        assert_eq!(
            load_cli_config().unwrap(),
            Some(CliConfig {
                api_url,
                token: Some("fixture-token".to_owned()),
            })
        );

        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api and triage-counter processes"]
    fn npm_scan_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
        })
        .unwrap();

        let lockfile = dir.path().join("package-lock.json");
        fs::write(
            &lockfile,
            r#"{"packages":{"node_modules/aegiscudo-benign-npm-fixture":{"version":"1.0.0","integrity":"sha512-x"}}}"#,
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("npm"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api and triage-counter processes"]
    fn pypi_scan_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
        })
        .unwrap();

        let requirements = dir.path().join("requirements.txt");
        fs::write(&requirements, "aegiscudo-benign-pypi-fixture==1.0.0\n").unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("pypi"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api process with seeded analysis data"]
    fn explain_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
        })
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("explain"),
            OsString::from("fresh-postinstall@0.1.0"),
            OsString::from("--ecosystem"),
            OsString::from("npm"),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api and triage-counter processes"]
    fn ci_preflight_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        unsafe { env::set_var(CONFIG_OVERRIDE_ENV, dir.path()); }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
        })
        .unwrap();

        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/aegiscudo-benign-npm-fixture":{"version":"1.0.0","integrity":"sha512-x"}}}"#,
        )
        .unwrap();

        env::set_current_dir(dir.path()).unwrap();
        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("ci"),
            OsString::from("preflight"),
            OsString::from("--format"),
            OsString::from("json"),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();
        env::set_current_dir(original_dir).unwrap();

        assert_eq!(exit_code, 0);
        unsafe { env::remove_var(CONFIG_OVERRIDE_ENV); }
    }
}
