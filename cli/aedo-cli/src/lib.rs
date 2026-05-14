use std::collections::{BTreeMap, BTreeSet};
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
use roxmltree;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod sbom;

use sbom::{
    SbomDocument, SbomFormat, SbomResolvedDecision, load_sbom_document,
    load_sbom_document_from_inputs, parse_maven_coordinate, render_sbom,
};

const DEFAULT_API_URL: &str = "http://127.0.0.1:8082";
const ACTOR_HEADER: &str = "x-aegiscudo-actor-id";
const CONFIG_OVERRIDE_ENV: &str = "AEDO_CONFIG_HOME";
const GITHUB_API_BASE_URL_ENV: &str = "AEGISCUDO_GITHUB_API_BASE_URL";
const GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";
const GITHUB_TAG_RESOLUTION_MAX_DEPTH: usize = 5;
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
    Sbom {
        #[command(subcommand)]
        command: SbomCommand,
    },
    Vex {
        #[command(subcommand)]
        command: VexCommand,
    },
    Explain(ExplainArgs),
    Risk(RiskArgs),
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
    #[arg(long, env = "AEGISCUDO_TENANT_ID")]
    tenant_id: Option<Uuid>,
    #[arg(long, env = "AEGISCUDO_POLICY_PROFILE_ID")]
    policy_profile_id: Option<Uuid>,
}

#[derive(Debug, Subcommand)]
enum ScanCommand {
    Npm(NpmScanArgs),
    Pnpm(PnpmScanArgs),
    Pypi(PypiScanArgs),
    Cargo(CargoScanArgs),
    Maven(MavenScanArgs),
    Rush(RushScanArgs),
    GithubActions(GitHubActionsScanArgs),
    Docker(NotYetSupportedArgs),
}

#[derive(Debug, Subcommand)]
enum SbomCommand {
    Generate(SbomGenerateArgs),
}

#[derive(Debug, Subcommand)]
enum VexCommand {
    Import(VexImportArgs),
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
struct SbomGenerateArgs {
    #[arg(long)]
    lockfile: Option<PathBuf>,
    #[arg(long)]
    requirements: Option<PathBuf>,
    /// Path to the output of `mvn dependency:tree`
    #[arg(long)]
    dependency_tree: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = SbomFormat::CyclonedxJson)]
    format: SbomFormat,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct VexImportArgs {
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    tenant_id: Uuid,
    #[arg(long, env = "AEGISCUDO_ACTOR_ID")]
    actor_id: Uuid,
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    expires_at: Option<String>,
}

#[derive(Debug, Args)]
struct CargoScanArgs {
    #[arg(long)]
    lockfile: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
}

#[derive(Debug, Args)]
struct MavenScanArgs {
    /// Path to pom.xml (direct dependencies; test/system scope excluded)
    #[arg(long)]
    pom: Option<PathBuf>,
    /// Path to the output of `mvn dependency:tree`
    #[arg(long)]
    dependency_tree: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
}

#[derive(Debug, Args)]
struct RushScanArgs {
    /// Path to rush.json
    #[arg(long)]
    config: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
}

#[derive(Debug, Args)]
struct GitHubActionsScanArgs {
    /// Directory containing workflow YAML files (e.g. .github/workflows)
    #[arg(long)]
    workflow_dir: PathBuf,
    /// Resolve mutable GitHub action tags to commit SHAs via the GitHub API.
    #[arg(long, default_value_t = false)]
    resolve_tags: bool,
    /// Explicit tenant context for remote GitHub Actions enrichment.
    #[arg(long)]
    tenant_id: Option<Uuid>,
    /// Explicit policy profile for remote GitHub Actions enrichment.
    #[arg(long)]
    policy_profile_id: Option<Uuid>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
}

#[derive(Debug, Args)]
struct NotYetSupportedArgs {}

#[derive(Debug, Args)]
struct ExplainArgs {
    package: String,
    #[arg(long, value_enum)]
    ecosystem: EcosystemArg,
}

#[derive(Debug, Args)]
struct RiskArgs {
    /// Package coordinate:
    ///   npm: "left-pad@1.0.0" or "@scope/pkg@1.0.0"
    ///   pypi: "requests@2.31.0"
    ///   cargo: "serde@1.0.0"
    ///   maven: "org.apache.commons:commons-lang3@3.14.0"
    package: String,
    #[arg(long, value_enum)]
    ecosystem: EcosystemArg,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output_format: OutputFormat,
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,
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
    Cargo,
    Maven,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_profile_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct CliScanSubmission {
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_profile_id: Option<Uuid>,
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
    #[serde(default)]
    decision_timestamp: Option<String>,
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

#[derive(Debug, Serialize)]
struct CliOpenVexImportSubmission {
    source: String,
    document: serde_json::Value,
    expiry_policy: CliOpenVexExpiryPolicy,
}

#[derive(Debug, Serialize)]
struct CliOpenVexExpiryPolicy {
    mode: CliOpenVexExpiryMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum CliOpenVexExpiryMode {
    Never,
    ExpiresAt,
}

#[derive(Debug, Deserialize)]
struct CliOpenVexApiResponse {
    id: Uuid,
    tenant_id: Uuid,
    source: String,
    document_id: String,
    statement_count: i32,
    imported_at: String,
}

#[derive(Debug, Deserialize)]
struct CliRiskApiResponse {
    coordinate: PackageCoordinate,
    decision: PolicyDecision,
    rationale: Vec<String>,
    trace_id: String,
    create_analysis_job: bool,
}

pub fn run(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<i32> {
    match Cli::parse_from(args).command {
        Command::Auth { command } => run_auth(command),
        Command::Scan { command } => run_scan(command),
        Command::Sbom { command } => run_sbom(command),
        Command::Vex { command } => run_vex(command),
        Command::Explain(args) => run_explain(args),
        Command::Risk(args) => run_risk(args),
        Command::Policy { command } => match command {
            PolicyCommand::Test(args) => run_policy_test(args),
        },
        Command::Ci { command } => match command {
            CiCommand::Preflight(args) => run_ci_preflight(args),
        },
    }
}

fn run_sbom(command: SbomCommand) -> anyhow::Result<i32> {
    match command {
        SbomCommand::Generate(args) => {
            let mut document = load_sbom_document_from_inputs(
                args.lockfile.as_deref(),
                args.requirements.as_deref(),
                args.dependency_tree.as_deref(),
            )?;
            if let Some(config) = load_sbom_enrichment_config(&document)? {
                enrich_sbom_with_decisions(&mut document, &config)?;
            } else if !document.supports_remote_decision_ecosystem() {
                eprintln!(
                    "skipping Aegiscudo decision enrichment for this SBOM because /v1/cli/scans currently supports only npm and pypi packages"
                );
            }
            let rendered = render_sbom(&document, args.format)?;
            if let Some(output) = args.output {
                fs::write(&output, rendered)
                    .with_context(|| format!("writing SBOM to {}", output.display()))?;
                println!("wrote {} to {}", args.format.label(), output.display());
            } else {
                println!("{rendered}");
            }
            Ok(0)
        }
    }
}

fn run_vex(command: VexCommand) -> anyhow::Result<i32> {
    match command {
        VexCommand::Import(args) => {
            let config = load_api_config()?;
            let document = load_openvex_document(&args.file)?;
            let source = args
                .source
                .unwrap_or_else(|| default_openvex_source(&args.file));
            let expiry_policy = cli_openvex_expiry_policy(args.expires_at);
            let response = submit_openvex_import_request(
                &config,
                args.tenant_id,
                args.actor_id,
                source,
                document,
                expiry_policy,
            )?;

            println!("imported OpenVEX document: {}", response.document_id);
            println!("stored id: {}", response.id);
            println!("tenant_id: {}", response.tenant_id);
            println!("source: {}", response.source);
            println!("statements: {}", response.statement_count);
            println!("imported_at: {}", response.imported_at);
            Ok(0)
        }
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
        let schema_json: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/policy.schema.json"))
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
    let report = submit_scan_report(source, false, findings, None)?;
    print_report(&report, args.format)?;
    Ok(exit_code(&report.findings, args.fail_on))
}

fn discover_ci_preflight_inputs(cwd: &Path) -> anyhow::Result<Vec<(String, Vec<ScanFinding>)>> {
    let supported_files = [
        (
            "package-lock.json",
            parse_package_lock as fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>,
        ),
        (
            "pnpm-lock.yaml",
            parse_pnpm_lock as fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>,
        ),
        (
            "requirements.txt",
            parse_requirements as fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>,
        ),
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
                token: args.token.or(existing.as_ref().and_then(|entry| entry.token.clone())),
                tenant_id: args.tenant_id.or(existing.as_ref().and_then(|entry| entry.tenant_id)),
                policy_profile_id: args
                    .policy_profile_id
                    .or(existing.as_ref().and_then(|entry| entry.policy_profile_id)),
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
                println!(
                    "local auth state already empty at {}",
                    config_path.display()
                );
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
                if let Some(tenant_id) = config.tenant_id {
                    println!("tenant_id: {tenant_id}");
                }
                if let Some(policy_profile_id) = config.policy_profile_id {
                    println!("policy_profile_id: {policy_profile_id}");
                }
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
        anyhow::bail!("HOME or XDG_CONFIG_HOME must be set to persist CLI configuration");
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
    fs::remove_file(&path).with_context(|| format!("removing CLI config {}", path.display()))?;
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
                None,
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
                None,
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
                None,
            )?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Cargo(args) => {
            let findings = parse_cargo_lock_scan(&args.lockfile)?;
            let report = submit_scan_report(
                args.lockfile.display().to_string(),
                false,
                findings,
                None,
            )?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Maven(args) => {
            let (source, findings) = match (&args.pom, &args.dependency_tree) {
                (Some(pom), _) => {
                    let findings = parse_maven_pom(pom)?;
                    (pom.display().to_string(), findings)
                }
                (None, Some(dep_tree)) => {
                    let findings = parse_maven_dependency_tree(dep_tree)?;
                    (dep_tree.display().to_string(), findings)
                }
                (None, None) => {
                    return Err(anyhow::anyhow!(
                        "aedo scan maven requires either --pom <pom.xml> or \
                         --dependency-tree <path>"
                    ));
                }
            };
            let report = submit_scan_report(source, false, findings, None)?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Rush(args) => {
            let (source, findings) = parse_rush_config(&args.config)?;
            let report = submit_scan_report(source, false, findings, None)?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::GithubActions(args) => {
            let findings = parse_github_actions_dir(&args.workflow_dir)?;
            let findings = if args.resolve_tags {
                resolve_github_action_tags(findings)?
            } else {
                findings
            };
            let report = submit_scan_report(
                args.workflow_dir.display().to_string(),
                false,
                findings,
                Some(CliEnrichmentContext {
                    tenant_id: args.tenant_id,
                    policy_profile_id: args.policy_profile_id,
                }),
            )?;
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Docker(_) => {
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

fn run_risk(args: RiskArgs) -> anyhow::Result<i32> {
    if args.output_format == OutputFormat::Sarif {
        anyhow::bail!(
            "SARIF output is not supported for aedo risk; use --output-format text or json"
        );
    }
    let coordinate = parse_risk_coordinate(&args.package, args.ecosystem)?;
    let config = load_api_config()?;
    let response = submit_risk_request(&config, &coordinate)?;

    match args.output_format {
        OutputFormat::Text => {
            println!("coordinate: {}", response.coordinate.purl());
            println!(
                "decision: {}",
                serde_json::to_string(&response.decision)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_owned()
            );
            for signal in &response.rationale {
                println!("  signal: {signal}");
            }
            if response.create_analysis_job {
                println!("note: an analysis job has been queued for asynchronous review");
            }
            println!("trace_id: {}", response.trace_id);
        }
        OutputFormat::Json => {
            let json_output = serde_json::json!({
                "coordinate": response.coordinate.purl(),
                "decision": response.decision,
                "rationale": response.rationale,
                "trace_id": response.trace_id,
                "create_analysis_job": response.create_analysis_job,
            });
            println!("{}", serde_json::to_string_pretty(&json_output)?);
        }
        OutputFormat::Sarif => unreachable!("sarif rejected above"),
    }

    Ok(match args.fail_on {
        FailOn::Warn => {
            if response.decision != PolicyDecision::Allow {
                1
            } else {
                0
            }
        }
        FailOn::Block => {
            if response.decision.is_blocking() {
                1
            } else {
                0
            }
        }
    })
}

fn parse_risk_coordinate(
    spec: &str,
    ecosystem: EcosystemArg,
) -> anyhow::Result<PackageCoordinate> {
    match ecosystem {
        EcosystemArg::Npm => parse_npm_explain_coordinate(spec),
        EcosystemArg::Pypi => parse_pypi_explain_coordinate(spec),
        EcosystemArg::Cargo => parse_cargo_risk_coordinate(spec),
        EcosystemArg::Maven => parse_maven_risk_coordinate(spec),
    }
}

fn parse_cargo_risk_coordinate(spec: &str) -> anyhow::Result<PackageCoordinate> {
    let trimmed = spec.trim();
    let (name, version) = trimmed
        .rsplit_once('@')
        .ok_or_else(|| anyhow::anyhow!("cargo risk expects <crate>@<version>"))?;
    let name = name.trim();
    let version = version.trim();
    if name.is_empty() || version.is_empty() {
        anyhow::bail!("cargo risk expects <crate>@<version>");
    }
    Ok(PackageCoordinate::new(
        PackageEcosystem::Cargo,
        name,
        Some(version),
        None::<String>,
    ))
}

fn parse_maven_risk_coordinate(spec: &str) -> anyhow::Result<PackageCoordinate> {
    // Expected format: <groupId>:<artifactId>@<version>
    let trimmed = spec.trim();
    let at_pos = trimmed
        .rfind('@')
        .ok_or_else(|| anyhow::anyhow!("maven risk expects <groupId>:<artifactId>@<version>"))?;
    let coordinate_part = &trimmed[..at_pos];
    let version = trimmed[at_pos + 1..].trim();
    if version.is_empty() {
        anyhow::bail!("maven risk expects <groupId>:<artifactId>@<version>");
    }
    let (group_id, artifact_id) = coordinate_part
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("maven risk expects <groupId>:<artifactId>@<version>"))?;
    let group_id = group_id.trim();
    let artifact_id = artifact_id.trim();
    if group_id.is_empty() || artifact_id.is_empty() {
        anyhow::bail!("maven risk expects <groupId>:<artifactId>@<version>");
    }
    Ok(PackageCoordinate::new(
        PackageEcosystem::Maven,
        artifact_id,
        Some(version),
        Some(group_id),
    ))
}

fn submit_risk_request(
    config: &CliConfig,
    coordinate: &PackageCoordinate,
) -> anyhow::Result<CliRiskApiResponse> {
    let client = Client::builder().timeout(SCAN_TIMEOUT).build()?;
    let mut request = client
        .post(format!("{}/v1/cli/risk", config.api_url))
        .json(&serde_json::json!({ "coordinate": coordinate }));
    if let Some(token) = config.token.as_deref() {
        request = request.bearer_auth(token);
    }
    request
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("submitting risk lookup to {}/v1/cli/risk", config.api_url))?
        .json()
        .with_context(|| format!("parsing risk response from {}", config.api_url))
}

fn enrich_sbom_with_decisions(
    document: &mut SbomDocument,
    config: &CliConfig,
) -> anyhow::Result<()> {
    let findings = document
        .decision_inputs()
        .into_iter()
        .map(|input| ScanFinding {
            coordinate: input.coordinate,
            integrity: input.integrity,
            decision: PolicyDecision::Allow,
        })
        .collect::<Vec<_>>();

    if findings.is_empty() {
        return Ok(());
    }

    let Some(enrichment_path) = scan_enrichment_path(&findings) else {
        eprintln!(
            "skipping Aegiscudo decision enrichment because these SBOM inputs do not map to a supported CLI enrichment path"
        );
        return Ok(());
    };

    let remote_findings = match submit_scan_findings(config, &findings, enrichment_path, None) {
        Ok(findings) => findings,
        Err(error) => {
            eprintln!(
                "skipping Aegiscudo decision enrichment because remote decision lookup failed: {error}"
            );
            return Ok(());
        }
    };
    let resolved_decisions = remote_findings
        .into_iter()
        .map(|finding| SbomResolvedDecision {
            coordinate: finding.coordinate,
            decision: finding.decision,
            decision_timestamp: finding.decision_timestamp,
        })
        .collect::<Vec<_>>();

    if let Err(error) = document.apply_resolved_decisions(&resolved_decisions) {
        eprintln!(
            "skipping Aegiscudo decision enrichment because remote decision response was invalid: {error}"
        );
    }

    Ok(())
}

fn parse_pnpm_lock(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut findings = Vec::new();
    let mut in_packages = false;
    let mut current_key: Option<String> = None;
    let mut current_integrity: Option<String> = None;
    let mut in_resolution = false;

    for line in contents.lines() {
        // Top-level YAML section header (no leading whitespace)
        if !line.starts_with(' ') {
            flush_pnpm_package(&mut findings, &mut current_key, &mut current_integrity);
            if !line.is_empty() {
                in_packages = line == "packages:";
            }
            in_resolution = false;
            continue;
        }

        if !in_packages {
            continue;
        }

        // 2-space-indented package key: "  'name@version':" or "  name@version:"
        if let Some(rest) = line.strip_prefix("  ") {
            if !rest.starts_with(' ') && rest.ends_with(':') {
                flush_pnpm_package(&mut findings, &mut current_key, &mut current_integrity);
                let key = rest
                    .trim_end_matches(':')
                    .trim_matches(|character| matches!(character, '\'' | '"'));
                current_key = Some(key.to_owned());
                in_resolution = false;
                continue;
            }
        }

        if current_key.is_some() {
            if let Some(rest) = line.strip_prefix("    resolution: {") {
                current_integrity = parse_pnpm_inline_integrity(rest);
                in_resolution = false;
                continue;
            }

            if line.trim() == "resolution:" {
                in_resolution = true;
                continue;
            }

            if in_resolution {
                if let Some(rest) = line.strip_prefix("      integrity: ") {
                    current_integrity = Some(parse_pnpm_yaml_scalar(rest));
                    continue;
                }

                if !line.starts_with("      ") {
                    in_resolution = false;
                }
            }
        }
    }

    flush_pnpm_package(&mut findings, &mut current_key, &mut current_integrity);

    Ok(findings)
}

fn flush_pnpm_package(
    findings: &mut Vec<ScanFinding>,
    current_key: &mut Option<String>,
    current_integrity: &mut Option<String>,
) {
    let Some(key) = current_key.take() else {
        current_integrity.take();
        return;
    };

    let (name, version) = split_pnpm_key(&key);
    if !name.is_empty() && !version.is_empty() {
        findings.push(finding(
            PackageEcosystem::Npm,
            name,
            Some(version),
            current_integrity.take(),
        ));
    } else {
        current_integrity.take();
    }
}

fn parse_pnpm_inline_integrity(value: &str) -> Option<String> {
    value
        .trim_end_matches('}')
        .split(',')
        .find_map(|entry| entry.trim().strip_prefix("integrity: "))
        .map(parse_pnpm_yaml_scalar)
}

fn parse_pnpm_yaml_scalar(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(',')
        .trim_matches('\'')
        .trim_matches('"')
        .to_owned()
}

/// Split a pnpm lockfile package key into (name, version).
/// Keys follow the format `name@version` for unscoped packages and
/// `@scope/name@version` for scoped packages.
fn split_pnpm_key(key: &str) -> (String, String) {
    let normalized = key.trim_matches('/');
    let base = normalized.split('(').next().unwrap_or(normalized);

    if base.starts_with('@') {
        if let Some(slash) = base.find('/') {
            if let Some(at) = base[slash + 1..].rfind('@') {
                let sep = slash + 1 + at;
                return (base[..sep].to_owned(), base[sep + 1..].to_owned());
            }
        }
    } else if let Some(at) = base.rfind('@') {
        return (base[..at].to_owned(), base[at + 1..].to_owned());
    }
    (base.to_owned(), String::new())
}

fn normalize_requirements_name(name: &str) -> Option<String> {
    let base = name.split('[').next().unwrap_or(name).trim();
    if base.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(base.len());
    let mut previous_separator = false;
    for character in base.chars() {
        match character {
            '-' | '_' | '.' => {
                if !previous_separator {
                    normalized.push('-');
                    previous_separator = true;
                }
            }
            _ => {
                normalized.push(character.to_ascii_lowercase());
                previous_separator = false;
            }
        }
    }

    (!normalized.is_empty()).then_some(normalized)
}

fn parse_requirements_hash_spec(value: &str) -> Option<String> {
    let (algorithm, digest) = value.split_once(':')?;
    match algorithm {
        "sha256" | "sha512" if !digest.trim().is_empty() => {
            Some(format!("{}:{}", algorithm, digest.trim()))
        }
        _ => None,
    }
}

fn extract_requirements_integrity(tokens: &[&str]) -> Option<String> {
    let mut hashes = BTreeSet::new();

    for (index, token) in tokens.iter().enumerate() {
        if let Some(value) = token.strip_prefix("--hash=") {
            if let Some(hash) = parse_requirements_hash_spec(value) {
                hashes.insert(hash);
            }
            continue;
        }
        if *token == "--hash" {
            if let Some(next) = tokens.get(index + 1) {
                if let Some(hash) = parse_requirements_hash_spec(next) {
                    hashes.insert(hash);
                }
            }
        }
        if let Some(hash) = parse_requirements_fragment_hash(token) {
            hashes.insert(hash);
        }
    }

    (hashes.len() == 1)
        .then(|| hashes.into_iter().next())
        .flatten()
}

fn parse_requirements_fragment_hash(token: &str) -> Option<String> {
    let fragment = token.split('#').nth(1)?;

    fragment.split('&').find_map(|part| {
        if let Some(digest) = part.strip_prefix("sha256=") {
            parse_requirements_hash_spec(&format!("sha256:{digest}"))
        } else if let Some(digest) = part.strip_prefix("sha512=") {
            parse_requirements_hash_spec(&format!("sha512:{digest}"))
        } else {
            None
        }
    })
}

fn requirements_parseable_content(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.contains(" @ ") || trimmed.starts_with("-e") || trimmed.starts_with("--editable") {
        trimmed
    } else {
        trimmed.split('#').next().unwrap_or(trimmed).trim()
    }
}

#[derive(Debug, Clone)]
struct ParsedRequirementFinding {
    name: String,
    version: Option<String>,
    integrity: Option<String>,
    constraint_eligible: bool,
}

fn parse_requirements_scan_line(line: &str) -> Option<ParsedRequirementFinding> {
    let content = requirements_parseable_content(line);
    if content.is_empty() || content.starts_with('-') {
        return None;
    }

    let content = content.split(';').next().unwrap_or(content).trim();
    if content.is_empty() {
        return None;
    }

    let tokens = content.split_whitespace().collect::<Vec<_>>();
    let package = *tokens.first()?;
    let integrity = extract_requirements_integrity(&tokens[1..]);
    let is_direct_reference = tokens.get(1) == Some(&"@");
    let (raw_name, version) = if is_direct_reference {
        (package.to_owned(), None)
    } else {
        package
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
            })
    };
    let name = normalize_requirements_name(&raw_name)?;

    Some(ParsedRequirementFinding {
        name,
        version,
        integrity,
        constraint_eligible: !is_direct_reference,
    })
}

fn parse_requirements_editable_name(line: &str, requirements_path: &Path) -> Option<String> {
    let spec = if let Some(value) = line.strip_prefix("-e") {
        value
    } else if let Some(value) = line.strip_prefix("--editable") {
        value
    } else {
        return None;
    };

    let spec = spec.trim_start_matches('=').trim();
    let egg = spec
        .split("#egg=")
        .nth(1)
        .or_else(|| spec.split("&egg=").nth(1));
    if let Some(egg) = egg {
        let egg = egg.split(['&', ' ', '\t']).next().unwrap_or(egg).trim();
        return normalize_requirements_name(egg);
    }

    editable_local_project_name(spec, requirements_path)
}

fn editable_local_project_name(spec: &str, requirements_path: &Path) -> Option<String> {
    let spec = spec.split([' ', '\t']).next().unwrap_or(spec).trim();
    let spec = spec.split(';').next().unwrap_or(spec).trim();
    let spec = normalize_local_editable_spec(spec)?;
    let candidate = if spec.is_absolute() {
        spec
    } else {
        requirements_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(spec)
    };
    if !candidate.is_dir() {
        return None;
    }

    editable_project_name_from_pyproject(&candidate)
        .or_else(|| editable_project_name_from_setup_cfg(&candidate))
}

fn normalize_local_editable_spec(spec: &str) -> Option<PathBuf> {
    if spec.is_empty() {
        return None;
    }

    let spec = strip_local_editable_path_extras(spec).trim();
    if spec.is_empty() {
        return None;
    }

    if spec.starts_with("file://") {
        return reqwest::Url::parse(spec).ok()?.to_file_path().ok();
    }

    let raw_spec = if let Some(path) = spec.strip_prefix("file:") {
        percent_decode_local_editable_path(path)?
    } else {
        if spec.contains("://")
            || spec.starts_with("git+")
            || spec.starts_with("hg+")
            || spec.starts_with("svn+")
            || spec.starts_with("bzr+")
        {
            return None;
        }
        spec.to_owned()
    };

    Some(PathBuf::from(raw_spec))
}

fn percent_decode_local_editable_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            let value = u8::from_str_radix(hex, 16).ok()?;
            decoded.push(value);
            index += 3;
            continue;
        }

        decoded.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(decoded).ok()
}

fn strip_local_editable_path_extras(spec: &str) -> &str {
    if spec.ends_with(']') {
        if let Some(index) = spec.rfind('[') {
            return &spec[..index];
        }
    }
    spec
}

fn editable_project_name_from_pyproject(project_root: &Path) -> Option<String> {
    let contents = fs::read_to_string(project_root.join("pyproject.toml")).ok()?;
    let document: toml::Value = toml::from_str(&contents).ok()?;

    document
        .get("project")
        .and_then(|project| project.get("name"))
        .and_then(|value| value.as_str())
        .and_then(normalize_requirements_name)
        .or_else(|| {
            document
                .get("tool")
                .and_then(|tool| tool.get("poetry"))
                .and_then(|poetry| poetry.get("name"))
                .and_then(|value| value.as_str())
                .and_then(normalize_requirements_name)
        })
}

fn editable_project_name_from_setup_cfg(project_root: &Path) -> Option<String> {
    let contents = fs::read_to_string(project_root.join("setup.cfg")).ok()?;
    let mut in_metadata = false;

    for raw_line in contents.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_metadata = trimmed.eq_ignore_ascii_case("[metadata]");
            continue;
        }
        if !in_metadata {
            continue;
        }
        let Some((key, value)) = trimmed
            .split_once('=')
            .or_else(|| trimmed.split_once(':'))
        else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("name") {
            return normalize_requirements_name(value.trim());
        }
    }

    None
}

fn package_lock_name_from_path(path: &str) -> Option<&str> {
    let trimmed = path.trim_matches('/');
    let name = trimmed
        .rsplit("/node_modules/")
        .next()
        .unwrap_or(trimmed)
        .trim_start_matches("node_modules/")
        .trim();
    (!name.is_empty()).then_some(name)
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
        #[serde(default)]
        dependencies: BTreeMap<String, PackageEntry>,
    }

    fn collect_legacy_package_lock_findings(
        raw_name: &str,
        entry: &PackageEntry,
        findings: &mut Vec<ScanFinding>,
    ) {
        findings.push(finding(
            PackageEcosystem::Npm,
            raw_name.to_owned(),
            entry.version.clone(),
            entry.integrity.clone(),
        ));

        for (child_name, child_entry) in &entry.dependencies {
            collect_legacy_package_lock_findings(child_name, child_entry, findings);
        }
    }

    let lockfile: PackageLock = serde_json::from_str(
        &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing npm lockfile {}", path.display()))?;

    let mut findings = Vec::new();
    for (package_path, entry) in lockfile.packages {
        if package_path.is_empty() || !package_path.contains("node_modules/") {
            continue;
        }
        let Some(name) = package_lock_name_from_path(&package_path).map(str::to_owned) else {
            continue;
        };
        findings.push(finding(
            PackageEcosystem::Npm,
            name,
            entry.version,
            entry.integrity,
        ));
    }
    if findings.is_empty() {
        for (name, entry) in lockfile.dependencies {
            collect_legacy_package_lock_findings(&name, &entry, &mut findings);
        }
    }
    Ok(findings)
}

fn parse_requirements(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    let mut entry_visited = BTreeSet::new();
    let mut constraint_visited = BTreeSet::new();
    let mut constraints = BTreeMap::new();
    let entries = collect_requirements_findings(
        path,
        &mut entry_visited,
        &mut constraint_visited,
        &mut constraints,
    )?;

    let entries = entries
        .into_iter()
        .map(|entry| apply_requirement_constraints(entry, &constraints))
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(dedupe_scan_findings(
        entries
            .into_iter()
            .map(|entry| {
                finding(
                    PackageEcosystem::Pypi,
                    entry.name,
                    entry.version,
                    entry.integrity,
                )
            })
            .collect(),
    ))
}

fn dedupe_scan_findings(findings: Vec<ScanFinding>) -> Vec<ScanFinding> {
    let mut merged: BTreeMap<String, ScanFinding> = BTreeMap::new();

    for finding in findings {
        let key = finding.coordinate.purl();
        if let Some(existing) = merged.get_mut(&key) {
            existing.integrity =
                merge_optional_values(existing.integrity.take(), finding.integrity);
        } else {
            merged.insert(key, finding);
        }
    }

    merged.into_values().collect()
}

fn parse_cargo_lock_scan(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    #[derive(Debug, Deserialize, Default)]
    struct CargoLock {
        #[serde(default)]
        package: Vec<CargoLockPackage>,
    }

    #[derive(Debug, Deserialize, Default)]
    struct CargoLockPackage {
        name: String,
        version: String,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        checksum: Option<String>,
    }

    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lockfile: CargoLock = toml::from_str(&contents)
        .with_context(|| format!("parsing Cargo.lock {}", path.display()))?;

    // Packages without a source field are local path/workspace members — skip them.
    let findings = lockfile
        .package
        .into_iter()
        .filter(|pkg| pkg.source.is_some())
        .map(|pkg| {
            let integrity = pkg.checksum.map(|cs| format!("sha256:{cs}"));
            finding(PackageEcosystem::Cargo, pkg.name, Some(pkg.version), integrity)
        })
        .collect();

    Ok(findings)
}

fn parse_maven_pom(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    let xml = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let doc = roxmltree::Document::parse(&xml)
        .with_context(|| format!("parsing POM XML: {}", path.display()))?;
    let root = doc.root_element();

    // Collect project-level metadata and <properties> for variable resolution.
    let mut project_version = String::new();
    let mut project_group_id = String::new();
    let mut props: BTreeMap<String, String> = BTreeMap::new();

    for child in root.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "version" => project_version = child.text().unwrap_or("").trim().to_owned(),
            "groupId" => project_group_id = child.text().unwrap_or("").trim().to_owned(),
            "properties" => {
                for prop in child.children().filter(|n| n.is_element()) {
                    if let Some(val) = prop.text() {
                        props.insert(prop.tag_name().name().to_owned(), val.trim().to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    // Built-in ${project.*} substitutions
    props.insert("project.version".to_owned(), project_version.clone());
    props.insert("project.groupId".to_owned(), project_group_id.clone());

    let resolve = |s: &str| -> String {
        let mut out = s.to_owned();
        for (k, v) in &props {
            out = out.replace(&format!("${{{k}}}"), v);
        }
        out
    };

    let mut findings = Vec::new();

    // Walk direct children of <project> looking for top-level <dependencies>.
    // We intentionally skip <dependencyManagement><dependencies> (version pinning only)
    // and any <dependencies> nested under <build><plugins><plugin>.
    for child in root.children().filter(|n| n.is_element()) {
        if child.tag_name().name() != "dependencies" {
            continue;
        }
        for dep in child.children().filter(|n| n.is_element()) {
            if dep.tag_name().name() != "dependency" {
                continue;
            }
            let mut group_id = String::new();
            let mut artifact_id = String::new();
            let mut version = String::new();
            let mut scope = String::new();

            for elem in dep.children().filter(|n| n.is_element()) {
                let text = elem.text().unwrap_or("").trim().to_owned();
                match elem.tag_name().name() {
                    "groupId" => group_id = resolve(&text),
                    "artifactId" => artifact_id = resolve(&text),
                    "version" => version = resolve(&text),
                    "scope" => scope = text,
                    _ => {}
                }
            }

            // Exclude test and system scope; empty/absent scope defaults to compile.
            if matches!(scope.as_str(), "test" | "system") {
                continue;
            }
            if group_id.is_empty() || artifact_id.is_empty() {
                continue;
            }

            findings.push(ScanFinding {
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Maven,
                    artifact_id,
                    if version.is_empty() { None } else { Some(version) },
                    Some(group_id),
                ),
                integrity: None,
                decision: PolicyDecision::Allow,
            });
        }
    }

    Ok(findings)
}

fn parse_maven_dependency_tree(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut findings = Vec::new();
    let mut first_line = true;

    for raw_line in contents.lines() {
        // Strip [INFO] prefix if present (output of `mvn dependency:tree`)
        let line = raw_line
            .strip_prefix("[INFO]")
            .map(|s| s.trim_start())
            .unwrap_or(raw_line)
            .trim();

        if line.is_empty()
            || line.starts_with("BUILD")
            || line.starts_with("--------")
            || line.starts_with("Total time")
            || line.starts_with("Finished at")
        {
            continue;
        }

        // Strip tree-decoration prefix characters: +, -, \, |, space
        let coord = line.trim_start_matches(|c: char| matches!(c, '+' | '-' | '\\' | '|' | ' '));

        // The first line that parses as a coordinate and has no tree decoration is the root
        // project — skip it.  Preamble lines emitted by the Maven build (e.g. "Scanning for
        // projects...\", plugin banners) are not coordinates and must not consume the slot.
        // Note: only +, \, and | are reliable tree-decoration leaders; - alone appears in
        // plugin banners (--- maven-plugin:version:goal @ project ---) and must not be treated
        // as tree decoration here.
        if first_line && !line.starts_with(['+', '\\', '|']) {
            if parse_maven_coordinate(coord).is_some() {
                first_line = false;
            }
            continue;
        }
        first_line = false;

        if let Some((group_id, artifact_id, version)) = parse_maven_coordinate(coord) {
            findings.push(ScanFinding {
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::Maven,
                    artifact_id,
                    Some(version),
                    Some(group_id),
                ),
                integrity: None,
                decision: PolicyDecision::Allow,
            });
        }
    }

    Ok(findings)
}

fn parse_rush_config(config_path: &PathBuf) -> anyhow::Result<(String, Vec<ScanFinding>)> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RushConfig {
        package_manager: String,
    }

    let contents = fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let config: RushConfig = serde_json::from_str(&contents)
        .with_context(|| format!("parsing rush.json {}", config_path.display()))?;

    let repo_root = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine repo root from {}", config_path.display()))?;

    let (lockfile, parser): (PathBuf, fn(&PathBuf) -> anyhow::Result<Vec<ScanFinding>>) =
        match config.package_manager.as_str() {
            "npm" => {
                let candidates = [
                    repo_root
                        .join("common")
                        .join("config")
                        .join("rush")
                        .join("npm-shrinkwrap.json"),
                    repo_root.join("common").join("temp").join("package-lock.json"),
                ];
                let found = candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Rush npm lockfile not found; run `rush install` first \
                         (looked for common/config/rush/npm-shrinkwrap.json and common/temp/package-lock.json)"
                    )
                })?;
                (found, parse_package_lock)
            }
            "pnpm" => {
                let candidates = [
                    repo_root
                        .join("common")
                        .join("config")
                        .join("rush")
                        .join("pnpm-lock.yaml"),
                    repo_root.join("common").join("temp").join("pnpm-lock.yaml"),
                ];
                let found = candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Rush pnpm lockfile not found; run `rush install` first \
                         (looked for common/config/rush/pnpm-lock.yaml and common/temp/pnpm-lock.yaml)"
                    )
                })?;
                (found, parse_pnpm_lock)
            }
            "yarn" => {
                anyhow::bail!(
                    "Rush yarn workspaces are not yet supported; \
                     run `rush install` and use `aedo scan npm --lockfile` or \
                     `aedo scan pnpm --lockfile` instead"
                );
            }
            other => {
                anyhow::bail!(
                    "unsupported Rush package manager '{other}'; \
                     supported values: npm, pnpm"
                );
            }
        };

    let source = lockfile.display().to_string();
    let findings = parser(&lockfile)?;
    Ok((source, findings))
}

fn parse_github_actions_dir(workflow_dir: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
    if !workflow_dir.exists() {
        anyhow::bail!(
            "workflow directory does not exist: {}",
            workflow_dir.display()
        );
    }

    let mut findings = Vec::new();
    let mut found_any_file = false;

    for ext in &["yml", "yaml"] {
        let pattern = format!("{}/*.{ext}", workflow_dir.display());
        for entry in glob::glob(&pattern)
            .with_context(|| {
                format!(
                    "searching for workflow files in {}",
                    workflow_dir.display()
                )
            })?
            .flatten()
        {
            found_any_file = true;
            let file_findings = parse_github_actions_file(&entry)
                .with_context(|| format!("parsing workflow file {}", entry.display()))?;
            findings.extend(file_findings);
        }
    }

    if !found_any_file {
        anyhow::bail!(
            "no workflow files (*.yml or *.yaml) found in {}",
            workflow_dir.display()
        );
    }

    Ok(dedupe_scan_findings(findings))
}

fn parse_github_actions_file(path: &Path) -> anyhow::Result<Vec<ScanFinding>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&contents)
        .with_context(|| format!("parsing workflow YAML {}", path.display()))?;

    let uses_refs = collect_uses_refs(&value);
    let mut findings = Vec::new();

    for uses_str in uses_refs {
        // Skip local composite actions and docker image references
        if uses_str.starts_with("./") || uses_str.starts_with("docker://") {
            continue;
        }
        if let Some(f) = parse_action_uses(&uses_str) {
            findings.push(f);
        }
    }

    Ok(findings)
}

fn collect_uses_refs(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::Mapping(map) => {
            let mut refs = Vec::new();
            for (key, val) in map {
                if key.as_str() == Some("uses") {
                    if let Some(s) = val.as_str() {
                        refs.push(s.to_owned());
                    }
                } else {
                    refs.extend(collect_uses_refs(val));
                }
            }
            refs
        }
        serde_yaml::Value::Sequence(seq) => seq.iter().flat_map(collect_uses_refs).collect(),
        _ => Vec::new(),
    }
}

fn parse_action_uses(uses: &str) -> Option<ScanFinding> {
    // Format: {owner}/{repo}@{ref} or {owner}/{repo}/{path}@{ref}
    let at_pos = uses.rfind('@')?;
    let ref_str = &uses[at_pos + 1..];
    let path_part = &uses[..at_pos];

    let slash_pos = path_part.find('/')?;
    let owner = &path_part[..slash_pos];
    let rest = &path_part[slash_pos + 1..];
    // repo is the first segment after owner (path may include subdirectory)
    let repo = rest.split('/').next()?;

    if owner.is_empty() || repo.is_empty() || ref_str.is_empty() {
        return None;
    }

    Some(github_actions_finding(owner, repo, ref_str))
}

fn github_actions_finding(owner: &str, repo: &str, ref_str: &str) -> ScanFinding {
    let decision = if is_sha_pinned(ref_str) {
        PolicyDecision::Allow
    } else {
        PolicyDecision::AllowWithWarning
    };
    ScanFinding {
        coordinate: PackageCoordinate::new(
            PackageEcosystem::GithubActions,
            repo,
            Some(ref_str),
            Some(owner),
        ),
        integrity: None,
        decision,
    }
}

fn is_sha_pinned(ref_str: &str) -> bool {
    ref_str.len() == 40 && ref_str.chars().all(|c| c.is_ascii_hexdigit())
}

fn resolve_github_action_tags(findings: Vec<ScanFinding>) -> anyhow::Result<Vec<ScanFinding>> {
    let resolver = GitHubTagResolver::from_env()?;
    let mut resolved = Vec::with_capacity(findings.len());

    for finding in findings {
        if finding.coordinate.ecosystem != PackageEcosystem::GithubActions {
            resolved.push(finding);
            continue;
        }

        let Some(owner) = finding.coordinate.namespace.as_deref() else {
            resolved.push(finding);
            continue;
        };
        let Some(reference) = finding.coordinate.version.as_deref() else {
            resolved.push(finding);
            continue;
        };
        if is_sha_pinned(reference) {
            resolved.push(finding);
            continue;
        }

        match resolver.resolve(owner, &finding.coordinate.name, reference) {
            Ok(sha) => resolved.push(github_actions_finding(owner, &finding.coordinate.name, &sha)),
            Err(error) => {
                eprintln!(
                    "warning: unable to resolve GitHub action tag {owner}/{}@{reference}: {error}",
                    finding.coordinate.name
                );
                resolved.push(finding);
            }
        }
    }

    Ok(resolved)
}

#[derive(Debug, Deserialize)]
struct GitHubRefResponse {
    object: GitHubRefObject,
}

#[derive(Debug, Deserialize)]
struct GitHubRefObject {
    sha: String,
    #[serde(rename = "type")]
    object_type: String,
}

#[derive(Debug, Deserialize)]
struct GitHubTagObjectResponse {
    object: GitHubRefObject,
}

struct GitHubTagResolver {
    client: Client,
    api_base_url: String,
    token: Option<String>,
}

impl GitHubTagResolver {
    fn from_env() -> anyhow::Result<Self> {
        let api_base_url = env::var(GITHUB_API_BASE_URL_ENV)
            .unwrap_or_else(|_| "https://api.github.com".to_owned());
        let token = env::var(GITHUB_TOKEN_ENV).ok();
        let client = Client::builder().timeout(SCAN_TIMEOUT).build()?;
        Ok(Self {
            client,
            api_base_url,
            token,
        })
    }

    fn resolve(&self, owner: &str, repo: &str, tag: &str) -> anyhow::Result<String> {
        let ref_url = format!(
            "{}/repos/{owner}/{repo}/git/ref/tags/{tag}",
            self.api_base_url.trim_end_matches('/')
        );
        let ref_response: GitHubRefResponse = self
            .request(&ref_url)
            .with_context(|| format!("resolving tag ref for {owner}/{repo}@{tag}"))?;

        let mut object = ref_response.object;
        for _ in 0..GITHUB_TAG_RESOLUTION_MAX_DEPTH {
            match object.object_type.as_str() {
                "commit" => return Ok(object.sha),
                "tag" => {
                    let tag_url = format!(
                        "{}/repos/{owner}/{repo}/git/tags/{}",
                        self.api_base_url.trim_end_matches('/'),
                        object.sha
                    );
                    let tag_response: GitHubTagObjectResponse = self.request(&tag_url).with_context(
                        || format!("resolving annotated tag object for {owner}/{repo}@{tag}"),
                    )?;
                    object = tag_response.object;
                }
                _ => {
                    anyhow::bail!(
                        "unsupported GitHub ref object type {} for {owner}/{repo}@{tag}",
                        object.object_type
                    )
                }
            }
        }

        anyhow::bail!(
            "exceeded annotated tag resolution depth for {owner}/{repo}@{tag}"
        )
    }

    fn request<T: for<'de> Deserialize<'de>>(&self, url: &str) -> anyhow::Result<T> {
        let mut request = self
            .client
            .get(url)
            .header("User-Agent", format!("aedo-cli/{}", env!("CARGO_PKG_VERSION")))
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send()?.error_for_status()?;
        Ok(response.json()?)
    }
}

fn collect_requirements_findings(
    path: &Path,
    entry_visited: &mut BTreeSet<PathBuf>,
    constraint_visited: &mut BTreeSet<PathBuf>,
    constraints: &mut BTreeMap<String, ParsedRequirementFinding>,
) -> anyhow::Result<Vec<ParsedRequirementFinding>> {
    let visit_key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !entry_visited.insert(visit_key) {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    for line in read_requirements_logical_lines(path)? {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(include_path) = parse_requirements_include(trimmed) {
            let nested_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(include_path);
            findings.extend(
                collect_requirements_findings(
                    &nested_path,
                    entry_visited,
                    constraint_visited,
                    constraints,
                )
                .with_context(|| {
                    format!(
                        "reading included requirements {} from {}",
                        nested_path.display(),
                        path.display()
                    )
                })?,
            );
            continue;
        }
        if let Some(constraint_path) = parse_requirements_constraint(trimmed) {
            let nested_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(constraint_path);
            collect_requirement_constraints(&nested_path, constraint_visited, constraints)
                .with_context(|| {
                    format!(
                        "reading constraint requirements {} from {}",
                        nested_path.display(),
                        path.display()
                    )
                })?;
            continue;
        }
        if let Some(name) = parse_requirements_editable_name(trimmed, path) {
            findings.push(ParsedRequirementFinding {
                name,
                version: None,
                integrity: None,
                constraint_eligible: false,
            });
            continue;
        }
        if trimmed.starts_with('-') {
            continue;
        }
        let Some(finding) = parse_requirements_scan_line(trimmed) else {
            continue;
        };
        findings.push(finding);
    }
    Ok(findings)
}

fn collect_requirement_constraints(
    path: &Path,
    visited: &mut BTreeSet<PathBuf>,
    constraints: &mut BTreeMap<String, ParsedRequirementFinding>,
) -> anyhow::Result<()> {
    let visit_key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(visit_key) {
        return Ok(());
    }

    for line in read_requirements_logical_lines(path)? {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(include_path) =
            parse_requirements_include(trimmed).or_else(|| parse_requirements_constraint(trimmed))
        {
            let nested_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(include_path);
            collect_requirement_constraints(&nested_path, visited, constraints).with_context(
                || {
                    format!(
                        "reading nested constraint requirements {} from {}",
                        nested_path.display(),
                        path.display()
                    )
                },
            )?;
            continue;
        }
        if trimmed.starts_with('-') {
            continue;
        }
        let Some(constraint) = parse_requirements_scan_line(trimmed) else {
            continue;
        };
        insert_requirement_constraint(constraints, constraint, path)?;
    }

    Ok(())
}

fn insert_requirement_constraint(
    constraints: &mut BTreeMap<String, ParsedRequirementFinding>,
    constraint: ParsedRequirementFinding,
    path: &Path,
) -> anyhow::Result<()> {
    if !constraint.constraint_eligible {
        anyhow::bail!(
            "requirements constraint {} from {} uses an unsupported direct reference",
            constraint.name,
            path.display()
        );
    }

    if let Some(existing) = constraints.get_mut(&constraint.name) {
        merge_requirement_constraint_value(
            &mut existing.version,
            constraint.version,
            &constraint.name,
            path,
            "version",
        )?;
        merge_requirement_constraint_value(
            &mut existing.integrity,
            constraint.integrity,
            &constraint.name,
            path,
            "hash",
        )?;
        return Ok(());
    }

    constraints.insert(constraint.name.clone(), constraint);
    Ok(())
}

fn merge_requirement_constraint_value(
    current: &mut Option<String>,
    next: Option<String>,
    name: &str,
    path: &Path,
    field: &str,
) -> anyhow::Result<()> {
    let Some(next_value) = next else {
        return Ok(());
    };

    match current {
        Some(existing) if existing != &next_value => anyhow::bail!(
            "requirements constraint {} from {} conflicts on {}",
            name,
            path.display(),
            field
        ),
        None => *current = Some(next_value),
        _ => {}
    }

    Ok(())
}

fn apply_requirement_constraints(
    mut entry: ParsedRequirementFinding,
    constraints: &BTreeMap<String, ParsedRequirementFinding>,
) -> anyhow::Result<ParsedRequirementFinding> {
    if !entry.constraint_eligible {
        return Ok(entry);
    }

    let Some(constraint) = constraints.get(&entry.name) else {
        return Ok(entry);
    };

    ensure_requirement_constraint_compatible(&entry, constraint)?;

    if entry.version.is_none() {
        entry.version = constraint.version.clone();
    }
    if entry.integrity.is_none()
        && (constraint.version.is_none() || constraint.version == entry.version)
    {
        entry.integrity = constraint.integrity.clone();
    }

    Ok(entry)
}

fn ensure_requirement_constraint_compatible(
    entry: &ParsedRequirementFinding,
    constraint: &ParsedRequirementFinding,
) -> anyhow::Result<()> {
    if let (Some(version), Some(constraint_version)) = (&entry.version, &constraint.version) {
        if version != constraint_version {
            anyhow::bail!(
                "requirement {} version {} conflicts with constraint version {}",
                entry.name,
                version,
                constraint_version
            );
        }
    }

    if let (Some(integrity), Some(constraint_integrity)) = (&entry.integrity, &constraint.integrity)
    {
        if integrity != constraint_integrity {
            anyhow::bail!(
                "requirement {} hash {} conflicts with constraint hash {}",
                entry.name,
                integrity,
                constraint_integrity
            );
        }
    }

    Ok(())
}

fn merge_optional_values(current: Option<String>, next: Option<String>) -> Option<String> {
    match (current, next) {
        (Some(left), Some(right)) if left == right => Some(left),
        (Some(_), Some(_)) => None,
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn read_requirements_logical_lines(path: &Path) -> anyhow::Result<Vec<String>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut logical_lines = Vec::new();
    let mut current = String::new();

    for raw_line in contents.lines() {
        let trimmed = raw_line.trim();
        if !current.is_empty() && trimmed.is_empty() {
            continue;
        }
        if current.is_empty() {
            current.push_str(trimmed);
        } else {
            current.push(' ');
            current.push_str(trimmed);
        }

        if current.ends_with('\\') {
            current.pop();
            current = current.trim_end().to_owned();
            continue;
        }

        if !current.trim().is_empty() {
            logical_lines.push(current.trim().to_owned());
        }
        current.clear();
    }

    if !current.trim().is_empty() {
        logical_lines.push(current.trim().to_owned());
    }

    Ok(logical_lines)
}

fn parse_requirements_include(line: &str) -> Option<&str> {
    let include = if let Some(value) = line.strip_prefix("-r") {
        value
    } else if let Some(value) = line.strip_prefix("--requirement") {
        value
    } else {
        return None;
    };

    let include = include.trim_start_matches('=').trim();
    let include = include.split('#').next().unwrap_or(include).trim();
    (!include.is_empty()).then_some(include)
}

fn parse_requirements_constraint(line: &str) -> Option<&str> {
    let include = if let Some(value) = line.strip_prefix("-c") {
        value
    } else if let Some(value) = line.strip_prefix("--constraint") {
        value
    } else {
        return None;
    };

    let include = include.trim_start_matches('=').trim();
    let include = include.split('#').next().unwrap_or(include).trim();
    (!include.is_empty()).then_some(include)
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
    override_context: Option<CliEnrichmentContext>,
) -> anyhow::Result<ScanReport> {
    let Some(enrichment_path) = scan_enrichment_path(&findings) else {
        return Ok(ScanReport {
            source,
            upload_manifest,
            findings,
        });
    };

    let Some(config) = load_scan_enrichment_config(enrichment_path)? else {
        return Ok(ScanReport {
            source,
            upload_manifest,
            findings,
        });
    };
    let remote_findings =
        submit_scan_findings(&config, &findings, enrichment_path, override_context)?;
    Ok(ScanReport {
        source,
        upload_manifest,
        findings: merge_scan_findings(findings, remote_findings)?,
    })
}

#[derive(Debug, Clone, Copy)]
struct CliEnrichmentContext {
    tenant_id: Option<Uuid>,
    policy_profile_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy)]
enum ScanEnrichmentPath {
    RegistryScan,
    GithubActions,
}

impl ScanEnrichmentPath {
    fn route(self) -> &'static str {
        match self {
            Self::RegistryScan => "/v1/cli/scans",
            Self::GithubActions => "/v1/cli/github-actions/enrich",
        }
    }
}

fn scan_enrichment_path(findings: &[ScanFinding]) -> Option<ScanEnrichmentPath> {
    let ecosystem = findings.first()?.coordinate.ecosystem.clone();
    if findings
        .iter()
        .any(|finding| finding.coordinate.ecosystem != ecosystem)
    {
        return None;
    }

    match ecosystem {
        PackageEcosystem::Npm | PackageEcosystem::Pypi => Some(ScanEnrichmentPath::RegistryScan),
        PackageEcosystem::GithubActions => Some(ScanEnrichmentPath::GithubActions),
        _ => None,
    }
}

fn load_api_config() -> anyhow::Result<CliConfig> {
    Ok(load_cli_config()?.unwrap_or_else(|| CliConfig {
        api_url: normalize_api_url(DEFAULT_API_URL),
        token: None,
        tenant_id: None,
        policy_profile_id: None,
    }))
}

fn load_scan_enrichment_config(
    enrichment_path: ScanEnrichmentPath,
) -> anyhow::Result<Option<CliConfig>> {
    match enrichment_path {
        ScanEnrichmentPath::RegistryScan => Ok(Some(load_api_config()?)),
        ScanEnrichmentPath::GithubActions => Ok(load_cli_config()?.map(|mut config| {
            config.api_url = normalize_api_url(&config.api_url);
            config
        })),
    }
}

fn load_openvex_document(path: &Path) -> anyhow::Result<serde_json::Value> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading OpenVEX file {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("parsing OpenVEX file {}", path.display()))
}

fn default_openvex_source(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn cli_openvex_expiry_policy(expires_at: Option<String>) -> CliOpenVexExpiryPolicy {
    match expires_at {
        Some(value) => CliOpenVexExpiryPolicy {
            mode: CliOpenVexExpiryMode::ExpiresAt,
            expires_at: Some(value),
        },
        None => CliOpenVexExpiryPolicy {
            mode: CliOpenVexExpiryMode::Never,
            expires_at: None,
        },
    }
}

fn sbom_enrichment_config_is_usable(config: &CliConfig) -> bool {
    let api_url = normalize_api_url(&config.api_url);
    if api_url.is_empty() {
        return false;
    }

    let Ok(parsed) = reqwest::Url::parse(&api_url) else {
        return false;
    };

    matches!(parsed.scheme(), "http" | "https")
}

fn load_sbom_enrichment_config(document: &SbomDocument) -> anyhow::Result<Option<CliConfig>> {
    if document.supports_remote_decision_enrichment() {
        return match load_cli_config() {
            Ok(Some(mut config)) if sbom_enrichment_config_is_usable(&config) => {
                config.api_url = normalize_api_url(&config.api_url);
                Ok(Some(config))
            }
            Ok(Some(config)) => {
                eprintln!(
                    "skipping Aegiscudo decision enrichment because CLI config API URL is unusable: {}",
                    config.api_url
                );
                Ok(None)
            }
            Ok(None) => Ok(None),
            Err(error) => {
                eprintln!(
                    "skipping Aegiscudo decision enrichment because CLI config could not be loaded: {error}"
                );
                Ok(None)
            }
        };
    }

    Ok(None)
}

fn submit_scan_findings(
    config: &CliConfig,
    findings: &[ScanFinding],
    enrichment_path: ScanEnrichmentPath,
    override_context: Option<CliEnrichmentContext>,
) -> anyhow::Result<Vec<CliScanApiFinding>> {
    let override_context = override_context.unwrap_or(CliEnrichmentContext {
        tenant_id: None,
        policy_profile_id: None,
    });
    let tenant_id = override_context.tenant_id.or(config.tenant_id);
    let policy_profile_id = override_context.policy_profile_id.or(config.policy_profile_id);
    if matches!(enrichment_path, ScanEnrichmentPath::GithubActions) && policy_profile_id.is_none() {
        anyhow::bail!(
            "GitHub Actions enrichment requires an explicit policy profile; configure one with `aedo auth login --policy-profile-id <uuid>` or pass `--policy-profile-id` to `aedo scan github-actions`"
        );
    }

    let client = Client::builder().timeout(SCAN_TIMEOUT).build()?;
    let submission = CliScanSubmission {
        tenant_id,
        policy_profile_id,
        packages: findings
            .iter()
            .map(|finding| CliScanSubmissionPackage {
                coordinate: finding.coordinate.clone(),
                artifact_sha256: artifact_sha256_from_finding(finding),
            })
            .collect(),
    };

    let mut request = client
        .post(format!("{}{}", config.api_url, enrichment_path.route()))
        .json(&submission);
    if let Some(token) = config.token.as_deref() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| {
            format!(
                "submitting CLI scan to {}{}",
                config.api_url,
                enrichment_path.route()
            )
        })?;
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
        .with_context(|| {
            format!(
                "submitting explain lookup to {}/v1/cli/explain",
                config.api_url
            )
        })?
        .json()
        .with_context(|| format!("parsing explain response from {}", config.api_url))
}

fn submit_openvex_import_request(
    config: &CliConfig,
    tenant_id: Uuid,
    actor_id: Uuid,
    source: String,
    document: serde_json::Value,
    expiry_policy: CliOpenVexExpiryPolicy,
) -> anyhow::Result<CliOpenVexApiResponse> {
    let client = Client::builder().timeout(SCAN_TIMEOUT).build()?;
    let mut request = client
        .post(format!(
            "{}/v1/tenants/{tenant_id}/openvex-documents",
            config.api_url
        ))
        .header(ACTOR_HEADER, actor_id.to_string())
        .json(&CliOpenVexImportSubmission {
            source,
            document,
            expiry_policy,
        });
    if let Some(token) = config.token.as_deref() {
        request = request.bearer_auth(token);
    }

    request
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| {
            format!(
                "importing OpenVEX document to {}/v1/tenants/{tenant_id}/openvex-documents",
                config.api_url
            )
        })?
        .json()
        .with_context(|| format!("parsing OpenVEX import response from {}", config.api_url))
}

fn parse_explain_coordinate(
    spec: &str,
    ecosystem: EcosystemArg,
) -> anyhow::Result<PackageCoordinate> {
    match ecosystem {
        EcosystemArg::Npm => parse_npm_explain_coordinate(spec),
        EcosystemArg::Pypi => parse_pypi_explain_coordinate(spec),
        EcosystemArg::Cargo | EcosystemArg::Maven => {
            anyhow::bail!(
                "aedo explain is only supported for npm and pypi packages; use aedo risk for other ecosystems"
            )
        }
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
        let (scope, package_name) = scoped_name.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("scoped npm packages must be formatted as @scope/name@version")
        })?;
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
    if candidate.len() == 64
        && candidate
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
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
        local.decision = stricter_scan_decision(local.decision.clone(), remote.decision);
    }

    Ok(local_findings)
}

fn stricter_scan_decision(local: PolicyDecision, remote: PolicyDecision) -> PolicyDecision {
    if decision_severity(&remote) > decision_severity(&local) {
        remote
    } else {
        local
    }
}

fn decision_severity(decision: &PolicyDecision) -> u8 {
    match decision {
        PolicyDecision::Allow => 0,
        PolicyDecision::AllowWithWarning => 1,
        PolicyDecision::FallbackToApprovedCandidate => 2,
        PolicyDecision::RequireHitlApproval => 3,
        PolicyDecision::QuarantinePendingAnalysis => 4,
        PolicyDecision::BlockPolicyViolation => 5,
        PolicyDecision::BlockKnownMalicious => 6,
    }
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
    use serde_json::json;
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
    fn validate_policy_file_accepts_scorecard_thresholds() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&json!({
                "id": "018f4a6f-55d0-7000-8000-000000000001",
                "tenant_id": "018f4a6f-55d0-7000-8000-000000000002",
                "version": "2026.05.12",
                "mode": "warn",
                "minimum_release_age_hours": 24,
                "known_vulnerability_threshold": {
                    "severity_floor": "high",
                    "kev_override": true
                },
                "scorecard_thresholds": {
                    "code_review": 9.5,
                    "branch_protection": 8.0,
                    "ci_cd": 9.0,
                    "maintained": 7.0,
                    "signed_releases": -1.0
                },
                "fail_closed": true,
                "rules": [
                    {
                        "id": "scorecard-branch-protection",
                        "signal": "scorecard_branch_protection_risk",
                        "action": "block",
                        "enabled": true
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        validate_policy_file(&path).expect("policy file with scorecard thresholds should validate");
    }

    #[test]
    fn validate_policy_file_accepts_current_default_fixture() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy-default.json");
        std::fs::write(&path, include_str!("../../../schemas/fixtures/policy.default.json")).unwrap();

        validate_policy_file(&path).expect("current default policy fixture should validate");
    }

    #[test]
    fn validate_policy_file_accepts_legacy_policy_fixture() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy-legacy.json");
        std::fs::write(
            &path,
            include_str!("../../../schemas/fixtures/policy.legacy-phase1.json"),
        )
        .unwrap();

        validate_policy_file(&path).expect("legacy Phase 1 policy fixture should remain valid");
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
    fn parses_nested_package_lock_names() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        fs::write(
            &path,
            r#"{"packages":{"node_modules/a/node_modules/b":{"version":"2.0.0"}}}"#,
        )
        .unwrap();

        let findings = parse_package_lock(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:npm/b@2.0.0");
    }

    #[test]
    fn parses_workspace_package_lock_names() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        fs::write(
            &path,
            r#"{"packages":{"packages/web/node_modules/react":{"version":"19.1.0"}}}"#,
        )
        .unwrap();

        let findings = parse_package_lock(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:npm/react@19.1.0");
    }

    #[test]
    fn parses_legacy_package_lock_transitives() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        fs::write(
            &path,
            r#"{
    "dependencies": {
        "a": {
            "version": "1.0.0",
            "dependencies": {
                "b": {
                    "version": "2.0.0"
                }
            }
        }
    }
}"#,
        )
        .unwrap();

        let findings = parse_package_lock(&path).unwrap();
        let purls = findings
            .into_iter()
            .map(|finding| finding.coordinate.purl())
            .collect::<Vec<_>>();

        assert_eq!(purls, vec!["pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"]);
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
    fn parses_pnpm_lock_multiline_resolution_and_missing_integrity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &path,
            "lockfileVersion: '9.0'\n\npackages:\n\n  react@19.1.0:\n    resolution:\n      integrity: 'sha512-react=='\n      tarball: https://example.invalid/react.tgz\n\n  left-pad@1.3.0:\n    resolution:\n      tarball: https://example.invalid/left-pad.tgz\n\nsnapshots:\n",
        )
        .unwrap();

        let findings = parse_pnpm_lock(&path).unwrap();

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].coordinate.purl(), "pkg:npm/react@19.1.0");
        assert_eq!(findings[0].integrity.as_deref(), Some("sha512-react=="));
        assert_eq!(findings[1].coordinate.purl(), "pkg:npm/left-pad@1.3.0");
        assert_eq!(findings[1].integrity, None);
    }

    #[test]
    fn parses_pnpm_lock_slash_prefixed_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &path,
            "lockfileVersion: '6.0'\n\npackages:\n  /ajv@8.20.0:\n    resolution: {integrity: sha512-abc==}\n\nsnapshots:\n",
        )
        .unwrap();

        let findings = parse_pnpm_lock(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:npm/ajv@8.20.0");
    }

    #[test]
    fn parses_pnpm_lock_double_quoted_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &path,
            "lockfileVersion: '9.0'\n\npackages:\n  \"@babel/core@7.29.0\":\n    resolution: {integrity: sha512-xyz==}\n\nsnapshots:\n",
        )
        .unwrap();

        let findings = parse_pnpm_lock(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:npm/babel/core@7.29.0");
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
    fn split_pnpm_key_strips_peer_suffixes() {
        assert_eq!(
            split_pnpm_key("react-dom@19.1.0(react@19.1.0)"),
            ("react-dom".to_owned(), "19.1.0".to_owned())
        );
        assert_eq!(
            split_pnpm_key("@scope/pkg@1.2.3(peer@4.5.6)"),
            ("@scope/pkg".to_owned(), "1.2.3".to_owned())
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
    fn parses_recursive_requirements_includes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        let dev = dir.path().join("requirements-dev.txt");
        let extra = dir.path().join("requirements-extra.txt");

        fs::write(
            &path,
            "--requirement=requirements-dev.txt\nrequests==2.32.0\n",
        )
        .unwrap();
        fs::write(&dev, "-r requirements-extra.txt\npytest==8.3.3\n").unwrap();
        fs::write(&extra, "urllib3==2.2.2\n").unwrap();

        let findings = parse_requirements(&path).unwrap();
        let purls = findings
            .into_iter()
            .map(|finding| finding.coordinate.purl())
            .collect::<Vec<_>>();
        let mut purls = purls;
        purls.sort();

        assert_eq!(
            purls,
            vec![
                "pkg:pypi/pytest@8.3.3",
                "pkg:pypi/requests@2.32.0",
                "pkg:pypi/urllib3@2.2.2",
            ]
        );
    }

    #[test]
    fn applies_constraints_to_unversioned_requirements() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        let constraints = dir.path().join("constraints.txt");
        fs::write(&path, "requests\n-c constraints.txt\n").unwrap();
        fs::write(&constraints, "requests==2.32.0\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/requests@2.32.0");
    }

    #[test]
    fn applies_constraints_across_normalized_requirement_names() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        let constraints = dir.path().join("constraints.txt");
        fs::write(&path, "Friendly_Bard\n-c constraints.txt\n").unwrap();
        fs::write(&constraints, "friendly.bard==1.2.3\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].coordinate.purl(),
            "pkg:pypi/friendly-bard@1.2.3"
        );
    }

    #[test]
    fn rejects_conflicting_requirement_constraints() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        let constraints = dir.path().join("constraints.txt");
        fs::write(&path, "requests==2.31.0\n-c constraints.txt\n").unwrap();
        fs::write(&constraints, "requests==2.32.0\n").unwrap();

        let error = parse_requirements(&path).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("conflicts with constraint version")
        );
    }

    #[test]
    fn rejects_direct_reference_constraints() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        let constraints = dir.path().join("constraints.txt");
        fs::write(&path, "demo\n-c constraints.txt\n").unwrap();
        fs::write(
            &constraints,
            "demo @ https://example.invalid/demo-1.0.0.tar.gz\n",
        )
        .unwrap();

        let error = parse_requirements(&path).unwrap_err();
        let error_text = format!("{error:#}");

        assert!(error_text.contains("unsupported direct reference"));
    }

    #[test]
    fn ignores_non_package_requirements_directives() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "--index-url https://example.invalid/simple\n--extra-index-url=https://mirror.invalid/simple\nrequests==2.32.0\n",
        )
        .unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/requests@2.32.0");
    }

    #[test]
    fn normalizes_requirements_pep_508_syntax() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "requests[socks]==2.32.0\nurllib3==2.2.2; python_version < \"3.13\"\n",
        )
        .unwrap();

        let findings = parse_requirements(&path).unwrap();
        let purls = findings
            .into_iter()
            .map(|finding| finding.coordinate.purl())
            .collect::<Vec<_>>();

        assert_eq!(
            purls,
            vec!["pkg:pypi/requests@2.32.0", "pkg:pypi/urllib3@2.2.2"]
        );
    }

    #[test]
    fn editable_local_requirements_use_setup_cfg_name_for_scan() {
        let dir = tempdir().unwrap();
        let package_dir = dir.path().join("pkg");
        let path = dir.path().join("requirements.txt");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(
            package_dir.join("setup.cfg"),
            "[metadata]\nname = Demo_Pkg\nversion = 0.1.0\n",
        )
        .unwrap();
        fs::write(&path, "--editable ./pkg\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo-pkg");
    }

    #[test]
    fn editable_local_requirements_use_pyproject_name_for_scan_root_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"scan-root-demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(&path, "-e .\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/scan-root-demo");
    }

    #[test]
    fn editable_local_requirements_with_extras_use_setup_cfg_name_for_scan() {
        let dir = tempdir().unwrap();
        let package_dir = dir.path().join("pkg");
        let path = dir.path().join("requirements.txt");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(package_dir.join("setup.cfg"), "[metadata]\nname = Demo_Extras\n").unwrap();
        fs::write(&path, "--editable ./pkg[test]\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo-extras");
    }

    #[test]
    fn editable_local_requirements_use_setup_cfg_colon_name_for_scan() {
        let dir = tempdir().unwrap();
        let package_dir = dir.path().join("pkg");
        let path = dir.path().join("requirements.txt");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(package_dir.join("setup.cfg"), "[metadata]\nname: Demo_Colon\n").unwrap();
        fs::write(&path, "--editable ./pkg\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo-colon");
    }

    #[test]
    fn editable_file_url_requirements_use_pyproject_name_for_scan() {
        let dir = tempdir().unwrap();
        let package_dir = dir.path().join("pkg");
        let path = dir.path().join("requirements.txt");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(
            package_dir.join("pyproject.toml"),
            "[project]\nname = \"demo-file-url\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(&path, format!("-e file://{}\n", package_dir.display())).unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo-file-url");
    }

    #[test]
    fn editable_file_url_requirements_decode_percent_escapes_for_scan() {
        let dir = tempdir().unwrap();
        let package_dir = dir.path().join("demo pkg");
        let path = dir.path().join("requirements.txt");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(
            package_dir.join("pyproject.toml"),
            "[project]\nname = \"demo-scan-percent\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let encoded_path = package_dir.display().to_string().replace(' ', "%20");
        fs::write(&path, format!("-e file://{}\n", encoded_path)).unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo-scan-percent");
    }

    #[test]
    fn editable_file_relative_requirements_decode_percent_escapes_for_scan() {
        let dir = tempdir().unwrap();
        let package_dir = dir.path().join("demo pkg");
        let path = dir.path().join("requirements.txt");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(
            package_dir.join("pyproject.toml"),
            "[project]\nname = \"demo-file-relative-scan\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(&path, "-e file:./demo%20pkg\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo-file-relative-scan");
    }

    #[test]
    fn remote_editable_requirements_without_egg_are_ignored() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(&path, "-e git+https://example.invalid/demo.git\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn editable_nested_include_paths_resolve_relative_for_scan() {
        let dir = tempdir().unwrap();
        let sub_dir = dir.path().join("sub");
        let package_dir = dir.path().join("pkg");
        let root = dir.path().join("requirements.txt");
        let nested = sub_dir.join("requirements.txt");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(
            package_dir.join("pyproject.toml"),
            "[project]\nname = \"demo-nested-scan\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(&root, "-r sub/requirements.txt\n").unwrap();
        fs::write(&nested, "-e ../pkg\n").unwrap();

        let findings = parse_requirements(&root).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo-nested-scan");
    }

    #[test]
    fn editable_local_requirements_prefer_egg_name_for_scan() {
        let dir = tempdir().unwrap();
        let package_dir = dir.path().join("pkg");
        let path = dir.path().join("requirements.txt");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(
            package_dir.join("pyproject.toml"),
            "[project]\nname = \"metadata-name\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(&path, "-e ./pkg#egg=override-name\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/override-name");
    }

    #[test]
    fn parses_requirements_direct_references_and_hashes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "demo @ https://example.invalid/demo-1.0.0.tar.gz --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo");
        assert_eq!(
            findings[0].integrity.as_deref(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
    }

    #[test]
    fn parses_requirements_direct_reference_hash_fragments() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "demo @ https://example.invalid/demo-1.0.0.tar.gz#sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo");
        assert_eq!(
            findings[0].integrity.as_deref(),
            Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    #[test]
    fn parses_editable_requirements() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(&path, "-e git+https://example.invalid/demo.git#egg=demo\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/demo");
    }

    #[test]
    fn deduplicates_duplicate_requirements() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(&path, "requests==2.32.0\nrequests==2.32.0\n").unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/requests@2.32.0");
    }

    #[test]
    fn conflicting_duplicate_requirement_hashes_drop_integrity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "requests==2.32.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nrequests==2.32.0 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/requests@2.32.0");
        assert!(findings[0].integrity.is_none());
    }

    #[test]
    fn conflicting_duplicate_requirement_hashes_drop_integrity_across_name_spellings() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "Friendly_Bard==1.2.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nfriendly-bard==1.2.3 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let findings = parse_requirements(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].coordinate.purl(),
            "pkg:pypi/friendly-bard@1.2.3"
        );
        assert!(findings[0].integrity.is_none());
    }

    #[test]
    fn npm_scan_reports_clear_error_for_yarn_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("yarn.lock");
        fs::write(
            &path,
            "# yarn lockfile v1\nleft-pad@1.3.0:\n  version \"1.3.0\"\n",
        )
        .unwrap();

        let error = parse_package_lock(&path).unwrap_err();
        assert!(error.to_string().contains("yarn.lock is not yet supported"));
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
            OsString::from("docker"),
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

        assert!(
            error
                .to_string()
                .contains("--upload-manifest is not yet supported")
        );
    }

    #[test]
    fn cli_config_round_trips_through_override_directory() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let config = CliConfig {
            api_url: "http://127.0.0.1:18002".to_owned(),
            token: Some("fixture-token".to_owned()),
            tenant_id: None,
            policy_profile_id: None,
        };
        let path = save_cli_config(&config).unwrap();
        assert!(path.exists());
        assert_eq!(load_cli_config().unwrap(), Some(config));
        assert!(clear_cli_config().unwrap());
        assert_eq!(load_cli_config().unwrap(), None);

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn auth_login_persists_config_after_health_probe() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer);
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
                tenant_id: None,
                policy_profile_id: None,
            })
        );

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
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
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

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
            tenant_id: None,
            policy_profile_id: None,
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
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_writes_cargo_lock_output() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let member_dir = dir.path().join("crates").join("demo-app");
        let member_manifest = member_dir.join("Cargo.toml");
        let lockfile = dir.path().join("Cargo.lock");
        let output = dir.path().join("sbom.cdx.json");
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(
            &manifest,
            r#"[workspace]
members = ["crates/demo-app"]
default-members = ["crates/demo-app"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &lockfile,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = ["serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--format"),
            OsString::from("cyclonedx-json"),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(
            rendered["metadata"]["component"]["purl"],
            "pkg:cargo/demo-app@0.1.0"
        );
        assert!(
            rendered["components"]
                .as_array()
                .unwrap()
                .iter()
                .any(|component| component["purl"] == "pkg:cargo/serde@1.0.228")
        );
    }

    #[test]
    fn maven_sbom_generate_writes_dependency_tree_output() {
        let dir = tempdir().unwrap();
        let dependency_tree = dir.path().join("dependency-tree.txt");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(
            &dependency_tree,
            r#"[INFO] com.example:demo-app:jar:1.0.0
[INFO] +- org.springframework:spring-core:jar:6.1.0:compile
[INFO] |  \- org.springframework:spring-jcl:jar:6.1.0:compile
[INFO] \- com.fasterxml.jackson.core:jackson-databind:jar:2.17.2:compile
"#,
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--dependency-tree"),
            dependency_tree.into_os_string(),
            OsString::from("--format"),
            OsString::from("cyclonedx-json"),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(
            rendered["metadata"]["component"]["purl"],
            "pkg:maven/com.example/demo-app@1.0.0"
        );
        assert!(
            rendered["components"]
                .as_array()
                .unwrap()
                .iter()
                .any(|component| component["purl"] == "pkg:maven/org.springframework/spring-core@6.1.0")
        );
        assert!(
            rendered["components"]
                .as_array()
                .unwrap()
                .iter()
                .any(|component| component["purl"] == "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.2")
        );
    }

    #[test]
    fn sbom_generate_skips_remote_decisions_for_cargo_lock_when_configured() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let manifest = dir.path().join("Cargo.toml");
        let lockfile = dir.path().join("Cargo.lock");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true

[workspace]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &lockfile,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = ["serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();
        save_cli_config(&CliConfig {
            api_url: "http://127.0.0.1:9".to_owned(),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--format"),
            OsString::from("cyclonedx-json"),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:cargo/serde@1.0.228")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_writes_unresolved_requirements_output_without_saved_cli_config() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(&requirements, "requests==2.32.0\n").unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/requests@2.32.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_uses_remote_decisions_for_requirements_when_configured() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(&requirements, "requests==2.32.0\n").unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/scans HTTP/1.1"));
                assert!(request.contains("\"ecosystem\":\"pypi\""));
                assert!(request.contains("\"name\":\"requests\""));
                assert!(request.contains("authorization: Bearer fixture-token"));

                let response = serde_json::json!({
                    "findings": [{
                        "coordinate": {
                            "ecosystem": "pypi",
                            "name": "requests",
                            "version": "2.32.0"
                        },
                        "decision": "ALLOW_WITH_WARNING",
                        "decision_timestamp": "2026-05-11T12:00:00Z"
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
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/requests@2.32.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision" && property["value"] == "ALLOW_WITH_WARNING"
        }));
        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_timestamp"
                && property["value"] == "2026-05-11T12:00:00Z"
        }));

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_ignores_invalid_remote_decision_payload_when_configured() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(&requirements, "requests==2.32.0\n").unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/scans HTTP/1.1"));

                let response = serde_json::json!({
                    "findings": [{
                        "coordinate": {
                            "ecosystem": "pypi",
                            "name": "urllib3",
                            "version": "2.32.0"
                        },
                        "decision": "ALLOW_WITH_WARNING",
                        "decision_timestamp": "2026-05-11T12:00:00Z"
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
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/requests@2.32.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_does_not_partially_apply_invalid_remote_decisions() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(&requirements, "requests==2.32.0\nurllib3==2.2.2\n").unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/scans HTTP/1.1"));

                let response = serde_json::json!({
                    "findings": [
                        {
                            "coordinate": {
                                "ecosystem": "pypi",
                                "name": "requests",
                                "version": "2.32.0"
                            },
                            "decision": "ALLOW_WITH_WARNING",
                            "decision_timestamp": "2026-05-11T12:00:00Z"
                        },
                        {
                            "coordinate": {
                                "ecosystem": "pypi",
                                "name": "different-package",
                                "version": "2.2.2"
                            },
                            "decision": "BLOCK_POLICY_VIOLATION",
                            "decision_timestamp": "2026-05-11T12:05:00Z"
                        }
                    ]
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
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        for purl in ["pkg:pypi/requests@2.32.0", "pkg:pypi/urllib3@2.2.2"] {
            let component = rendered["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|component| component["purl"] == purl)
                .unwrap();
            let properties = component["properties"].as_array().unwrap();

            assert!(properties.iter().any(|property| {
                property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
            }));
        }

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_uses_remote_decisions_for_package_lock_when_configured() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("package-lock.json");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(
            &lockfile,
            r#"{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "@scope/pkg": "1.0.0"
      }
    },
    "node_modules/@scope/pkg": {
      "version": "1.0.0",
      "integrity": "sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  }
}"#,
        )
        .unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/scans HTTP/1.1"));
                assert!(request.contains("\"ecosystem\":\"npm\""));
                assert!(request.contains("\"name\":\"pkg\""));
                assert!(request.contains("\"namespace\":\"scope\""));
                assert!(request.contains("authorization: Bearer fixture-token"));

                let response = serde_json::json!({
                    "findings": [{
                        "coordinate": {
                            "ecosystem": "npm",
                            "name": "pkg",
                            "version": "1.0.0",
                            "namespace": "scope"
                        },
                        "decision": "BLOCK_POLICY_VIOLATION",
                        "decision_timestamp": "2026-05-11T12:30:00Z"
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
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:npm/scope/pkg@1.0.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision"
                && property["value"] == "BLOCK_POLICY_VIOLATION"
        }));
        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_timestamp"
                && property["value"] == "2026-05-11T12:30:00Z"
        }));

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_writes_unresolved_pnpm_output_without_saved_cli_config() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("pnpm-lock.yaml");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(
            &lockfile,
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left-pad:
        version: 1.3.0
packages:
  left-pad@1.3.0:
    resolution:
      integrity: sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
snapshots:
  left-pad@1.3.0: {}
"#,
        )
        .unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:npm/left-pad@1.3.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_ignores_unreachable_config_for_package_lock() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("package-lock.json");
        let output = dir.path().join("sbom.cdx.json");
        fs::write(
            &lockfile,
            r#"{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "@scope/pkg": "1.0.0"
      }
    },
    "node_modules/@scope/pkg": {
      "version": "1.0.0",
      "integrity": "sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  }
}"#,
        )
        .unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }
        save_cli_config(&CliConfig {
            api_url: "http://127.0.0.1:9/".to_owned(),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:npm/scope/pkg@1.0.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_writes_requested_cyclonedx_compatibility_format() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx16.json");
        fs::write(&requirements, "requests==2.32.0\n").unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--format"),
            OsString::from("cyclonedx-1.6-json"),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(rendered["specVersion"], "1.6");

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_accepts_spdx_alias_format() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.spdx.json");
        fs::write(&requirements, "requests==2.32.0\n").unwrap();

        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--format"),
            OsString::from("spdx-json"),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(rendered["spdxVersion"], "SPDX-2.3");

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_ignores_malformed_config_for_unsupported_cargo_lock() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let lockfile = dir.path().join("Cargo.lock");
        let output = dir.path().join("sbom.cdx.json");
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        fs::write(dir.path().join("aedo.json"), "{ definitely-not-valid-json").unwrap();
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true

[workspace]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &lockfile,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
"#,
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(
            rendered["metadata"]["component"]["purl"],
            "pkg:cargo/demo-app@0.1.0"
        );

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_ignores_malformed_config_for_supported_requirements() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx.json");
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        fs::write(dir.path().join("aedo.json"), "{ definitely-not-valid-json").unwrap();
        fs::write(&requirements, "requests==2.32.0\n").unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/requests@2.32.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_ignores_unusable_config_for_supported_requirements() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx.json");
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        fs::write(&requirements, "requests==2.32.0\n").unwrap();
        save_cli_config(&CliConfig {
            api_url: "not a url".to_owned(),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/requests@2.32.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn sbom_generate_ignores_unreachable_config_for_supported_requirements() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        let output = dir.path().join("sbom.cdx.json");
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        fs::write(&requirements, "requests==2.32.0\n").unwrap();
        save_cli_config(&CliConfig {
            api_url: "http://127.0.0.1:9/".to_owned(),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("sbom"),
            OsString::from("generate"),
            OsString::from("--requirements"),
            requirements.into_os_string(),
            OsString::from("--output"),
            output.clone().into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        let rendered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/requests@2.32.0")
            .unwrap();
        let properties = component["properties"].as_array().unwrap();

        assert!(properties.iter().any(|property| {
            property["name"] == "aegiscudo:decision_status" && property["value"] == "unresolved"
        }));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn empty_cargo_sbom_documents_do_not_attempt_remote_enrichment() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &lockfile,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(&lockfile), None).unwrap();

        assert!(!document.supports_remote_decision_enrichment());
        assert!(load_sbom_enrichment_config(&document).unwrap().is_none());
    }

    #[test]
    fn empty_requirements_sbom_documents_do_not_attempt_remote_enrichment() {
        let dir = tempdir().unwrap();
        let requirements = dir.path().join("requirements.txt");
        fs::write(&requirements, "\n# no packages\n").unwrap();

        let document = load_sbom_document(None, Some(&requirements)).unwrap();

        assert!(document.supports_remote_decision_ecosystem());
        assert!(!document.supports_remote_decision_enrichment());
        assert!(load_sbom_enrichment_config(&document).unwrap().is_none());
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
    fn risk_parses_cargo_coordinate() {
        let coordinate = parse_risk_coordinate("serde@1.0.0", EcosystemArg::Cargo).unwrap();

        assert_eq!(coordinate.ecosystem, PackageEcosystem::Cargo);
        assert_eq!(coordinate.name, "serde");
        assert_eq!(coordinate.version.as_deref(), Some("1.0.0"));
        assert_eq!(coordinate.namespace, None);
    }

    #[test]
    fn risk_parses_maven_coordinate() {
        let coordinate = parse_risk_coordinate(
            "org.apache.commons:commons-lang3@3.14.0",
            EcosystemArg::Maven,
        )
        .unwrap();

        assert_eq!(coordinate.ecosystem, PackageEcosystem::Maven);
        assert_eq!(coordinate.name, "commons-lang3");
        assert_eq!(coordinate.version.as_deref(), Some("3.14.0"));
        assert_eq!(coordinate.namespace.as_deref(), Some("org.apache.commons"));
    }

    #[test]
    fn risk_cargo_rejects_missing_version() {
        let error = parse_risk_coordinate("serde", EcosystemArg::Cargo).unwrap_err();

        assert!(error.to_string().contains("cargo risk expects <crate>@<version>"));
    }

    #[test]
    fn risk_maven_rejects_missing_colon() {
        let error =
            parse_risk_coordinate("commons-lang3@3.14.0", EcosystemArg::Maven).unwrap_err();

        assert!(error
            .to_string()
            .contains("maven risk expects <groupId>:<artifactId>@<version>"));
    }

    #[test]
    fn risk_maven_rejects_missing_version() {
        let error = parse_risk_coordinate(
            "org.apache.commons:commons-lang3",
            EcosystemArg::Maven,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("maven risk expects <groupId>:<artifactId>@<version>"));
    }

    #[test]
    fn risk_returns_decision_from_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("risk-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 8192];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/risk HTTP/1.1"));
                assert!(request.contains("\"ecosystem\":\"cargo\""));
                assert!(request.contains("\"name\":\"serde\""));
                assert!(request.contains("authorization: Bearer risk-token"));

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "registry_config_id": "018f4a6f-55d0-7000-8000-000000000201",
                    "policy_profile_id": "018f4a6f-55d0-7000-8000-000000000301",
                    "coordinate": {
                        "ecosystem": "cargo",
                        "name": "serde",
                        "version": "1.0.0",
                        "namespace": null
                    },
                    "decision": "ALLOW",
                    "rationale": ["no known malicious indicators"],
                    "trace_id": "risk-trace-1",
                    "create_analysis_job": false
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
            OsString::from("risk"),
            OsString::from("serde@1.0.0"),
            OsString::from("--ecosystem"),
            OsString::from("cargo"),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn risk_npm_uses_risk_route_with_scoped_coordinate() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("risk-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 8192];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/risk HTTP/1.1"));
                assert!(request.contains("\"ecosystem\":\"npm\""));
                assert!(request.contains("\"name\":\"pkg\""));
                assert!(request.contains("\"namespace\":\"scope\""));
                assert!(request.contains("\"version\":\"1.2.3\""));
                assert!(request.contains("authorization: Bearer risk-token"));

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "registry_config_id": "018f4a6f-55d0-7000-8000-000000000201",
                    "policy_profile_id": "018f4a6f-55d0-7000-8000-000000000301",
                    "coordinate": {
                        "ecosystem": "npm",
                        "name": "pkg",
                        "version": "1.2.3",
                        "namespace": "scope"
                    },
                    "decision": "ALLOW",
                    "rationale": ["no known malicious indicators"],
                    "trace_id": "risk-trace-npm",
                    "create_analysis_job": false
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
            OsString::from("risk"),
            OsString::from("@scope/pkg@1.2.3"),
            OsString::from("--ecosystem"),
            OsString::from("npm"),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn risk_exits_1_when_blocking_decision_and_fail_on_block() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: None,
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 8192];
                let _ = stream.read(&mut buffer).unwrap();

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "registry_config_id": "018f4a6f-55d0-7000-8000-000000000201",
                    "policy_profile_id": "018f4a6f-55d0-7000-8000-000000000301",
                    "coordinate": {
                        "ecosystem": "maven",
                        "name": "log4j-core",
                        "version": "2.14.0",
                        "namespace": "org.apache.logging.log4j"
                    },
                    "decision": "BLOCK_KNOWN_MALICIOUS",
                    "rationale": ["known-malicious indicator"],
                    "trace_id": "risk-trace-blocked",
                    "create_analysis_job": false
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
            OsString::from("risk"),
            OsString::from("org.apache.logging.log4j:log4j-core@2.14.0"),
            OsString::from("--ecosystem"),
            OsString::from("maven"),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();

        assert_eq!(exit_code, 1);

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn risk_rejects_sarif_output_format() {
        // SARIF is rejected before any coordinate parsing or API call.
        let error = run([
            OsString::from("aedo"),
            OsString::from("risk"),
            OsString::from("serde@1.0.0"),
            OsString::from("--ecosystem"),
            OsString::from("cargo"),
            OsString::from("--output-format"),
            OsString::from("sarif"),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("SARIF"));
    }

    #[test]
    fn risk_exits_1_when_fail_on_warn_and_allow_with_warning() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: None,
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer).unwrap();

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "registry_config_id": "018f4a6f-55d0-7000-8000-000000000201",
                    "policy_profile_id": "018f4a6f-55d0-7000-8000-000000000301",
                    "coordinate": {
                        "ecosystem": "npm",
                        "name": "left-pad",
                        "version": "1.3.0"
                    },
                    "decision": "ALLOW_WITH_WARNING",
                    "rationale": ["scorecard_branch_protection_risk"],
                    "trace_id": "risk-trace-warn",
                    "create_analysis_job": false
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
            OsString::from("risk"),
            OsString::from("left-pad@1.3.0"),
            OsString::from("--ecosystem"),
            OsString::from("npm"),
            OsString::from("--fail-on"),
            OsString::from("warn"),
        ])
        .unwrap();

        // AllowWithWarning is not Allow — fail-on warn exits 1.
        assert_eq!(exit_code, 1);

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn risk_exits_0_when_fail_on_block_and_allow_with_warning() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: None,
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer).unwrap();

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "registry_config_id": "018f4a6f-55d0-7000-8000-000000000201",
                    "policy_profile_id": "018f4a6f-55d0-7000-8000-000000000301",
                    "coordinate": {
                        "ecosystem": "pypi",
                        "name": "requests",
                        "version": "2.31.0"
                    },
                    "decision": "ALLOW_WITH_WARNING",
                    "rationale": ["scorecard_low_score"],
                    "trace_id": "risk-trace-warn-2",
                    "create_analysis_job": true
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
            OsString::from("risk"),
            OsString::from("requests@2.31.0"),
            OsString::from("--ecosystem"),
            OsString::from("pypi"),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();

        // AllowWithWarning is not blocking — fail-on block exits 0.
        assert_eq!(exit_code, 0);

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn explain_uses_remote_summary_from_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
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
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn ci_preflight_discovers_package_lock_in_current_dir() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

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
        tenant_id: None,
        policy_profile_id: None,
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
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn ci_preflight_aggregates_supported_files_across_ecosystems() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"sha512-x"}}}"#,
        )
        .unwrap();
        fs::write(dir.path().join("requirements.txt"), "requests==2.32.0\n").unwrap();
        fs::write(dir.path().join("requirements-dev.txt"), "pytest==8.3.3\n").unwrap();

        let aggregated =
            aggregate_ci_preflight_findings(discover_ci_preflight_inputs(dir.path()).unwrap())
                .unwrap();

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
                    Some(
                        "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                    ),
                )],
            ),
            (
                "pnpm-lock.yaml".to_owned(),
                vec![finding(
                    PackageEcosystem::Npm,
                    "left-pad".to_owned(),
                    Some("1.3.0".to_owned()),
                    Some(
                        "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_owned(),
                    ),
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

        assert!(
            error
                .to_string()
                .contains("found no supported dependency files")
        );
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
        fs::write(nested.join("requirements.txt"), "requests==2.32.0\n").unwrap();

        let error = discover_ci_preflight_inputs(dir.path()).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("found no supported dependency files")
        );
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
                decision_timestamp: None,
            }],
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("did not align with request order")
        );
    }

    #[test]
    fn merge_scan_findings_preserves_stricter_local_decision_when_remote_allows() {
        let merged = merge_scan_findings(
            vec![github_actions_finding("actions", "checkout", "v4")],
            vec![CliScanApiFinding {
                coordinate: PackageCoordinate::new(
                    PackageEcosystem::GithubActions,
                    "checkout",
                    Some("v4"),
                    Some("actions"),
                ),
                decision: PolicyDecision::Allow,
                decision_timestamp: None,
            }],
        )
        .expect("merge should succeed");

        assert_eq!(merged[0].decision, PolicyDecision::AllowWithWarning);
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api process"]
    fn auth_login_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

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
                tenant_id: None,
                policy_profile_id: None,
            })
        );

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn vex_import_uses_remote_api_with_actor_and_token() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let openvex_file = dir.path().join("openvex.json");
        fs::write(
            &openvex_file,
            serde_json::to_vec_pretty(&json!({
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://fixtures.aegiscudo.invalid/openvex/acme-2026-001",
                "author": "CLI Fixture",
                "timestamp": "2026-05-12T08:00:00Z",
                "version": 1,
                "statements": [{
                    "vulnerability": { "name": "CVE-2026-0001" },
                    "products": [{ "@id": "pkg:npm/left-pad@1.3.0" }],
                    "status": "not_affected"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let tenant_id = Uuid::now_v7();
        let actor_id = Uuid::now_v7();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("fixture-token".to_owned()),
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 8192];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains(&format!(
                    "POST /v1/tenants/{tenant_id}/openvex-documents HTTP/1.1"
                )));
                assert!(request.contains(&format!("{ACTOR_HEADER}: {actor_id}")));
                assert!(request.contains("authorization: Bearer fixture-token"));
                assert!(request.contains("\"source\":\"fixture-openvex.json\""));
                assert!(request.contains("\"mode\":\"expires-at\""));
                assert!(request.contains("\"@context\":\"https://openvex.dev/ns/v0.2.0\""));

                let response = serde_json::json!({
                    "id": Uuid::now_v7(),
                    "tenant_id": tenant_id,
                    "source": "fixture-openvex.json",
                    "document_id": "https://fixtures.aegiscudo.invalid/openvex/acme-2026-001",
                    "statement_count": 1,
                    "imported_at": "2026-05-12T08:10:00Z"
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
            OsString::from("vex"),
            OsString::from("import"),
            OsString::from("--file"),
            openvex_file.as_os_str().to_os_string(),
            OsString::from("--tenant-id"),
            OsString::from(tenant_id.to_string()),
            OsString::from("--actor-id"),
            OsString::from(actor_id.to_string()),
            OsString::from("--source"),
            OsString::from("fixture-openvex.json"),
            OsString::from("--expires-at"),
            OsString::from("2026-05-31T12:00:00Z"),
        ])
        .unwrap();

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn vex_import_defaults_to_never_expiry_when_omitted() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let openvex_file = dir.path().join("openvex.json");
        fs::write(
            &openvex_file,
            serde_json::to_vec_pretty(&json!({
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://fixtures.aegiscudo.invalid/openvex/acme-2026-002",
                "author": "CLI Fixture",
                "timestamp": "2026-05-12T08:00:00Z",
                "version": 1,
                "statements": [{
                    "vulnerability": { "name": "CVE-2026-0003" },
                    "products": [{ "@id": "pkg:pypi/requests@2.31.0" }],
                    "status": "fixed"
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let tenant_id = Uuid::now_v7();
        let actor_id = Uuid::now_v7();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: None,
        tenant_id: None,
        policy_profile_id: None,
        })
        .unwrap();

        let expected_source = default_openvex_source(&openvex_file);
        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 8192];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("\"mode\":\"never\""));
                assert!(!request.contains("\"expires_at\""));
                assert!(request.contains(&format!("\"source\":\"{}\"", expected_source)));

                let response = serde_json::json!({
                    "id": Uuid::now_v7(),
                    "tenant_id": tenant_id,
                    "source": expected_source,
                    "document_id": "https://fixtures.aegiscudo.invalid/openvex/acme-2026-002",
                    "statement_count": 1,
                    "imported_at": "2026-05-12T08:12:00Z"
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
            OsString::from("vex"),
            OsString::from("import"),
            OsString::from("--file"),
            openvex_file.as_os_str().to_os_string(),
            OsString::from("--tenant-id"),
            OsString::from(tenant_id.to_string()),
            OsString::from("--actor-id"),
            OsString::from(actor_id.to_string()),
        ])
        .unwrap();

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }

        assert_eq!(exit_code, 0);
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api and triage-counter processes"]
    fn npm_scan_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
            tenant_id: None,
            policy_profile_id: None,
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
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api and triage-counter processes"]
    fn pypi_scan_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
            tenant_id: None,
            policy_profile_id: None,
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
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api process with seeded analysis data"]
    fn explain_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
            tenant_id: None,
            policy_profile_id: None,
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
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    #[ignore = "requires live local aegiscudo-api and triage-counter processes"]
    fn ci_preflight_works_against_live_local_api() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let original_dir = env::current_dir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }

        let api_url = env::var("AEGISCUDO_API_URL_FOR_TEST")
            .unwrap_or_else(|_| "http://127.0.0.1:18002".to_owned());
        save_cli_config(&CliConfig {
            api_url,
            token: Some("fixture-token".to_owned()),
            tenant_id: None,
            policy_profile_id: None,
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
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    // ── aedo scan cargo ───────────────────────────────────────────────────────

    #[test]
    fn scan_cargo_parses_registry_packages_from_lock() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(
            &lockfile,
            r#"version = 3

[[package]]
name = "my-project"
version = "0.1.0"

[[package]]
name = "anyhow"
version = "1.0.75"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a4668cab20f99d8c0180d2558d2158bab88cc6d431a9b0f55cf6851cde2e5eb40"

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "25dd0975d2f8f669f5d0440a1bab66ae0d9f87c7c4e4c8bc7af4e46f2a21a5e8"
"#,
        )
        .unwrap();

        let findings = parse_cargo_lock_scan(&lockfile).unwrap();
        assert_eq!(findings.len(), 2);

        let purls: Vec<_> = findings.iter().map(|f| f.coordinate.purl()).collect();
        assert!(purls.contains(&"pkg:cargo/anyhow@1.0.75".to_owned()));
        assert!(purls.contains(&"pkg:cargo/serde@1.0.193".to_owned()));

        let anyhow = findings.iter().find(|f| f.coordinate.name == "anyhow").unwrap();
        assert_eq!(
            anyhow.integrity.as_deref(),
            Some("sha256:a4668cab20f99d8c0180d2558d2158bab88cc6d431a9b0f55cf6851cde2e5eb40")
        );
    }

    #[test]
    fn scan_cargo_skips_path_and_workspace_members() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(
            &lockfile,
            r#"version = 3

[[package]]
name = "workspace-root"
version = "0.1.0"

[[package]]
name = "workspace-member"
version = "0.2.0"

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef0000000000000000000000000000000000000000000000000000000000"
"#,
        )
        .unwrap();

        let findings = parse_cargo_lock_scan(&lockfile).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.name, "tokio");
    }

    #[test]
    fn scan_cargo_includes_git_source_packages() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(
            &lockfile,
            r#"version = 3

[[package]]
name = "my-git-dep"
version = "0.5.0"
source = "git+https://github.com/example/my-git-dep?rev=abc123#abc123deadbeef"
"#,
        )
        .unwrap();

        let findings = parse_cargo_lock_scan(&lockfile).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.name, "my-git-dep");
        assert!(findings[0].integrity.is_none());
    }

    #[test]
    fn scan_cargo_empty_lock_produces_no_findings() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(&lockfile, "version = 3\n").unwrap();

        let findings = parse_cargo_lock_scan(&lockfile).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_cargo_missing_lockfile_errors() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("Cargo.lock");
        let err = parse_cargo_lock_scan(&lockfile).unwrap_err();
        assert!(format!("{err}").contains("reading"));
    }

    #[test]
    fn scan_cargo_invalid_toml_errors() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(&lockfile, "NOT VALID TOML !!##$$").unwrap();
        let err = parse_cargo_lock_scan(&lockfile).unwrap_err();
        assert!(format!("{err:#}").contains("parsing Cargo.lock"));
    }

    #[test]
    fn scan_cargo_command_exits_zero_on_all_allowed() {
        let dir = tempdir().unwrap();
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(
            &lockfile,
            r#"version = 3

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef0000000000000000000000000000000000000000000000000000000000"
"#,
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("cargo"),
            OsString::from("--lockfile"),
            lockfile.into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    // ── aedo scan maven --dependency-tree ─────────────────────────────────────

    #[test]
    fn scan_maven_parses_dependency_tree_output() {
        let dir = tempdir().unwrap();
        let dep_tree = dir.path().join("dependency-tree.txt");
        fs::write(
            &dep_tree,
            "[INFO] com.example:my-project:jar:1.0.0\n\
             [INFO] +- junit:junit:jar:4.13.1:test\n\
             [INFO] |  \\- org.hamcrest:hamcrest-core:jar:1.1:test\n\
             [INFO] \\- commons-io:commons-io:jar:2.11.0:compile\n",
        )
        .unwrap();

        let findings = parse_maven_dependency_tree(&dep_tree).unwrap();
        assert_eq!(findings.len(), 3);

        let purls: Vec<_> = findings.iter().map(|f| f.coordinate.purl()).collect();
        assert!(purls.contains(&"pkg:maven/junit/junit@4.13.1".to_owned()));
        assert!(
            purls.contains(&"pkg:maven/org.hamcrest/hamcrest-core@1.1".to_owned())
        );
        assert!(
            purls.contains(&"pkg:maven/commons-io/commons-io@2.11.0".to_owned())
        );
    }

    #[test]
    fn scan_maven_parses_dependency_tree_without_info_prefix() {
        let dir = tempdir().unwrap();
        let dep_tree = dir.path().join("dep-tree.txt");
        fs::write(
            &dep_tree,
            "com.example:my-project:jar:1.0.0\n\
             +- junit:junit:jar:4.13.1:test\n\
             \\- commons-io:commons-io:jar:2.11.0:compile\n",
        )
        .unwrap();

        let findings = parse_maven_dependency_tree(&dep_tree).unwrap();
        assert_eq!(findings.len(), 2);

        let purls: Vec<_> = findings.iter().map(|f| f.coordinate.purl()).collect();
        assert!(purls.contains(&"pkg:maven/junit/junit@4.13.1".to_owned()));
        assert!(
            purls.contains(&"pkg:maven/commons-io/commons-io@2.11.0".to_owned())
        );
    }

    #[test]
    fn scan_maven_parses_classifier_dependency() {
        let dir = tempdir().unwrap();
        let dep_tree = dir.path().join("dep-tree.txt");
        // 6-part format: groupId:artifactId:type:classifier:version:scope
        fs::write(
            &dep_tree,
            "com.example:root:jar:1.0.0\n\
             +- com.example:some-dep:jar:sources:2.3.4:compile\n",
        )
        .unwrap();

        let findings = parse_maven_dependency_tree(&dep_tree).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:maven/com.example/some-dep@2.3.4");
    }

    #[test]
    fn scan_maven_requires_dependency_tree_argument() {
        let error = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("maven"),
        ])
        .unwrap_err();
        assert!(format!("{error:#}").contains("--dependency-tree"));
    }

    #[test]
    fn scan_maven_command_exits_zero_on_all_allowed() {
        let dir = tempdir().unwrap();
        let dep_tree = dir.path().join("dep-tree.txt");
        fs::write(
            &dep_tree,
            "[INFO] com.example:my-project:jar:1.0.0\n\
             [INFO] \\- junit:junit:jar:4.13.1:test\n",
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("maven"),
            OsString::from("--dependency-tree"),
            dep_tree.into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn scan_maven_skips_preamble_lines_before_root_coordinate() {
        // Real `mvn dependency:tree` output starts with preamble lines like
        // "Scanning for projects..." and the plugin banner before the root coordinate.
        // These must not consume the first_line root-skip slot.
        let dir = tempdir().unwrap();
        let dep_tree = dir.path().join("dep-tree.txt");
        fs::write(
            &dep_tree,
            "[INFO] Scanning for projects...\n\
             [INFO] \n\
             [INFO] --- maven-dependency-plugin:3.6.3:tree (default-cli) @ my-project ---\n\
             [INFO] com.example:my-project:jar:1.0.0\n\
             [INFO] +- junit:junit:jar:4.13.1:test\n\
             [INFO] \\- commons-io:commons-io:jar:2.11.0:compile\n\
             [INFO] \n\
             [INFO] BUILD SUCCESS\n",
        )
        .unwrap();

        let findings = parse_maven_dependency_tree(&dep_tree).unwrap();
        assert_eq!(findings.len(), 2, "root project must not appear as a finding");

        let purls: Vec<_> = findings.iter().map(|f| f.coordinate.purl()).collect();
        assert!(purls.contains(&"pkg:maven/junit/junit@4.13.1".to_owned()));
        assert!(
            purls.contains(&"pkg:maven/commons-io/commons-io@2.11.0".to_owned())
        );
    }

    // ── aedo scan maven --pom ─────────────────────────────────────────────────

    #[test]
    fn scan_maven_pom_parses_compile_and_runtime_deps() {
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
      <version>2.11.0</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.9</version>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.1</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>native-dep</artifactId>
      <version>1.0</version>
      <scope>system</scope>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();

        let findings = parse_maven_pom(&pom).unwrap();

        assert_eq!(findings.len(), 2, "only compile/runtime deps should be included");
        let purls: Vec<_> = findings.iter().map(|f| f.coordinate.purl()).collect();
        assert!(purls.contains(&"pkg:maven/commons-io/commons-io@2.11.0".to_owned()));
        assert!(purls.contains(&"pkg:maven/org.slf4j/slf4j-api@2.0.9".to_owned()));
    }

    #[test]
    fn scan_maven_pom_resolves_property_variables() {
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>2.0.0</version>
  <properties>
    <junit.version>4.13.2</junit.version>
    <slf4j.version>2.0.9</slf4j.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${junit.version}</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();

        let findings = parse_maven_pom(&pom).unwrap();
        // junit is test scope — excluded; slf4j should be present with resolved version
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.purl(), "pkg:maven/org.slf4j/slf4j-api@2.0.9");
    }

    #[test]
    fn scan_maven_pom_resolves_project_version() {
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>3.1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();

        let findings = parse_maven_pom(&pom).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.version.as_deref(), Some("3.1.0"));
    }

    #[test]
    fn scan_maven_pom_skips_dependency_management() {
        // <dependencyManagement><dependencies> entries are version pinning only —
        // they are not direct dependencies and must not appear in findings.
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-bom</artifactId>
  <version>1.0.0</version>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>commons-io</groupId>
        <artifactId>commons-io</artifactId>
        <version>2.11.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>"#,
        )
        .unwrap();

        let findings = parse_maven_pom(&pom).unwrap();
        assert!(findings.is_empty(), "dependencyManagement entries are not direct dependencies");
    }

    #[test]
    fn scan_maven_pom_errors_on_missing_file() {
        let dir = tempdir().unwrap();
        let err = parse_maven_pom(&dir.path().join("nonexistent.xml")).unwrap_err();
        assert!(format!("{err:#}").contains("nonexistent.xml"));
    }

    #[test]
    fn scan_maven_pom_errors_on_malformed_xml() {
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(&pom, "<project><unclosed>").unwrap();
        let err = parse_maven_pom(&pom).unwrap_err();
        assert!(format!("{err:#}").contains("parsing POM XML"));
    }

    #[test]
    fn scan_maven_pom_returns_empty_for_no_dependencies() {
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>empty</artifactId>
  <version>1.0.0</version>
</project>"#,
        )
        .unwrap();

        let findings = parse_maven_pom(&pom).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_maven_pom_handles_unresolved_version() {
        // If a version can't be resolved (e.g. from parent POM), version = None
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <!-- version managed by parent POM — not present here -->
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();

        let findings = parse_maven_pom(&pom).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].coordinate.version.is_none());
        assert_eq!(findings[0].coordinate.namespace.as_deref(), Some("org.springframework"));
    }

    #[test]
    fn scan_maven_pom_command_exits_zero() {
        let dir = tempdir().unwrap();
        let pom = dir.path().join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>ci-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>commons-lang3</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("maven"),
            OsString::from("--pom"),
            pom.into_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    // ── aedo scan rush ────────────────────────────────────────────────────────

    #[test]
    fn scan_rush_parses_npm_lockfile() {
        let dir = tempdir().unwrap();
        // Write rush.json
        fs::write(
            dir.path().join("rush.json"),
            r#"{"rushVersion":"5.99.0","packageManager":"npm","projects":[]}"#,
        )
        .unwrap();
        // Write the shared npm lockfile that Rush generates
        let lockfile_dir = dir
            .path()
            .join("common")
            .join("config")
            .join("rush");
        fs::create_dir_all(&lockfile_dir).unwrap();
        fs::write(
            lockfile_dir.join("npm-shrinkwrap.json"),
            r#"{"packages":{"node_modules/left-pad":{"version":"1.3.0","integrity":"sha512-abc"}}}"#,
        )
        .unwrap();

        let (source, findings) =
            parse_rush_config(&dir.path().join("rush.json")).unwrap();
        assert!(source.contains("npm-shrinkwrap.json"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.name, "left-pad");
    }

    #[test]
    fn scan_rush_parses_pnpm_lockfile() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("rush.json"),
            r#"{"rushVersion":"5.99.0","packageManager":"pnpm","projects":[]}"#,
        )
        .unwrap();
        let lockfile_dir = dir.path().join("common").join("config").join("rush");
        fs::create_dir_all(&lockfile_dir).unwrap();
        fs::write(
            lockfile_dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '6.0'\npackages:\n  /left-pad@1.3.0:\n    resolution:\n      integrity: sha512-abc\n",
        )
        .unwrap();

        let (source, findings) =
            parse_rush_config(&dir.path().join("rush.json")).unwrap();
        assert!(source.contains("pnpm-lock.yaml"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.name, "left-pad");
    }

    #[test]
    fn scan_rush_errors_on_yarn() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("rush.json"),
            r#"{"rushVersion":"5.99.0","packageManager":"yarn","projects":[]}"#,
        )
        .unwrap();

        let err = parse_rush_config(&dir.path().join("rush.json")).unwrap_err();
        assert!(format!("{err:#}").contains("yarn"));
    }

    #[test]
    fn scan_rush_errors_on_missing_lockfile() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("rush.json"),
            r#"{"rushVersion":"5.99.0","packageManager":"npm","projects":[]}"#,
        )
        .unwrap();

        let err = parse_rush_config(&dir.path().join("rush.json")).unwrap_err();
        assert!(format!("{err:#}").contains("rush install"));
    }

    #[test]
    fn scan_rush_falls_back_to_common_temp_npm_lockfile() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("rush.json"),
            r#"{"rushVersion":"5.99.0","packageManager":"npm","projects":[]}"#,
        )
        .unwrap();
        // Only the temp fallback path exists (not the primary config path)
        let temp_dir = dir.path().join("common").join("temp");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            temp_dir.join("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.21","integrity":"sha512-xyz"}}}"#,
        )
        .unwrap();

        let (source, findings) =
            parse_rush_config(&dir.path().join("rush.json")).unwrap();
        assert!(source.contains("package-lock.json"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.name, "lodash");
    }

    // ── aedo scan github-actions ──────────────────────────────────────────────

    #[test]
    fn scan_github_actions_allows_sha_pinned_actions() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675\n",
        )
        .unwrap();

        let findings = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].decision, PolicyDecision::Allow);
        assert_eq!(findings[0].coordinate.namespace.as_deref(), Some("actions"));
        assert_eq!(findings[0].coordinate.name, "checkout");
        assert_eq!(
            findings[0].coordinate.version.as_deref(),
            Some("a81bbbf8298c0fa03ea29cdc473d45769f953675")
        );
    }

    #[test]
    fn scan_github_actions_warns_on_mutable_tags() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: actions/checkout@v4\n      \
             - uses: actions/setup-node@main\n",
        )
        .unwrap();

        let findings = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap();
        assert_eq!(findings.len(), 2);
        assert!(
            findings.iter().all(|f| f.decision == PolicyDecision::AllowWithWarning)
        );
    }

    #[test]
    fn resolve_github_action_tags_converts_tag_to_commit_sha() {
        let _guard = env_lock().lock().unwrap();
        let findings = vec![github_actions_finding("actions", "checkout", "v4")];
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            assert_eq!(request.url(), "/repos/actions/checkout/git/ref/tags/v4");
            request
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"a81bbbf8298c0fa03ea29cdc473d45769f953675","type":"commit"}}"#,
                ))
                .unwrap();
        });

        unsafe {
            env::set_var(GITHUB_API_BASE_URL_ENV, &base_url);
        }
        let resolved = resolve_github_action_tags(findings).unwrap();
        unsafe {
            env::remove_var(GITHUB_API_BASE_URL_ENV);
        }
        handle.join().unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].decision, PolicyDecision::Allow);
        assert_eq!(
            resolved[0].coordinate.version.as_deref(),
            Some("a81bbbf8298c0fa03ea29cdc473d45769f953675")
        );
    }

    #[test]
    fn resolve_github_action_tags_follows_annotated_tag_objects() {
        let _guard = env_lock().lock().unwrap();
        let findings = vec![github_actions_finding("actions", "checkout", "v4")];
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = std::thread::spawn(move || {
            let first = server.recv().unwrap();
            assert_eq!(first.url(), "/repos/actions/checkout/git/ref/tags/v4");
            first
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"tagobject123","type":"tag"}}"#,
                ))
                .unwrap();

            let second = server.recv().unwrap();
            assert_eq!(second.url(), "/repos/actions/checkout/git/tags/tagobject123");
            second
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"a81bbbf8298c0fa03ea29cdc473d45769f953675","type":"commit"}}"#,
                ))
                .unwrap();
        });

        unsafe {
            env::set_var(GITHUB_API_BASE_URL_ENV, &base_url);
        }
        let resolved = resolve_github_action_tags(findings).unwrap();
        unsafe {
            env::remove_var(GITHUB_API_BASE_URL_ENV);
        }
        handle.join().unwrap();

        assert_eq!(resolved[0].decision, PolicyDecision::Allow);
        assert_eq!(
            resolved[0].coordinate.version.as_deref(),
            Some("a81bbbf8298c0fa03ea29cdc473d45769f953675")
        );
    }

    #[test]
    fn resolve_github_action_tags_follows_nested_annotated_tag_objects() {
        let _guard = env_lock().lock().unwrap();
        let findings = vec![github_actions_finding("actions", "checkout", "v4")];
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = std::thread::spawn(move || {
            let first = server.recv().unwrap();
            assert_eq!(first.url(), "/repos/actions/checkout/git/ref/tags/v4");
            first
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"tagobject123","type":"tag"}}"#,
                ))
                .unwrap();

            let second = server.recv().unwrap();
            assert_eq!(second.url(), "/repos/actions/checkout/git/tags/tagobject123");
            second
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"tagobject456","type":"tag"}}"#,
                ))
                .unwrap();

            let third = server.recv().unwrap();
            assert_eq!(third.url(), "/repos/actions/checkout/git/tags/tagobject456");
            third
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"a81bbbf8298c0fa03ea29cdc473d45769f953675","type":"commit"}}"#,
                ))
                .unwrap();
        });

        unsafe {
            env::set_var(GITHUB_API_BASE_URL_ENV, &base_url);
        }
        let resolved = resolve_github_action_tags(findings).unwrap();
        unsafe {
            env::remove_var(GITHUB_API_BASE_URL_ENV);
        }
        handle.join().unwrap();

        assert_eq!(resolved[0].decision, PolicyDecision::Allow);
        assert_eq!(
            resolved[0].coordinate.version.as_deref(),
            Some("a81bbbf8298c0fa03ea29cdc473d45769f953675")
        );
    }

    #[test]
    fn resolve_github_action_tags_keeps_warning_when_resolution_fails() {
        let _guard = env_lock().lock().unwrap();
        let findings = vec![github_actions_finding("actions", "checkout", "v4")];
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            request
                .respond(
                    tiny_http::Response::from_string("not found").with_status_code(404),
                )
                .unwrap();
        });

        unsafe {
            env::set_var(GITHUB_API_BASE_URL_ENV, &base_url);
        }
        let resolved = resolve_github_action_tags(findings).unwrap();
        unsafe {
            env::remove_var(GITHUB_API_BASE_URL_ENV);
        }
        handle.join().unwrap();

        assert_eq!(resolved[0].decision, PolicyDecision::AllowWithWarning);
        assert_eq!(resolved[0].coordinate.version.as_deref(), Some("v4"));
    }

    #[test]
    fn resolve_github_action_tags_keeps_warning_for_non_commit_tag_objects() {
        let _guard = env_lock().lock().unwrap();
        let findings = vec![github_actions_finding("actions", "checkout", "v4")];
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = std::thread::spawn(move || {
            let first = server.recv().unwrap();
            assert_eq!(first.url(), "/repos/actions/checkout/git/ref/tags/v4");
            first
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"tagobject123","type":"tag"}}"#,
                ))
                .unwrap();

            let second = server.recv().unwrap();
            assert_eq!(second.url(), "/repos/actions/checkout/git/tags/tagobject123");
            second
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"blobsha","type":"blob"}}"#,
                ))
                .unwrap();
        });

        unsafe {
            env::set_var(GITHUB_API_BASE_URL_ENV, &base_url);
        }
        let resolved = resolve_github_action_tags(findings).unwrap();
        unsafe {
            env::remove_var(GITHUB_API_BASE_URL_ENV);
        }
        handle.join().unwrap();

        assert_eq!(resolved[0].decision, PolicyDecision::AllowWithWarning);
        assert_eq!(resolved[0].coordinate.version.as_deref(), Some("v4"));
    }

    #[test]
    fn resolve_github_action_tags_uses_github_token() {
        let _guard = env_lock().lock().unwrap();
        let findings = vec![github_actions_finding("actions", "checkout", "v4")];
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            assert_eq!(request.url(), "/repos/actions/checkout/git/ref/tags/v4");
            let auth_header = request
                .headers()
                .iter()
                .find(|header| header.field.equiv("Authorization"))
                .map(|header| header.value.as_str().to_owned());
            assert_eq!(auth_header.as_deref(), Some("Bearer fixture-token"));
            request
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"a81bbbf8298c0fa03ea29cdc473d45769f953675","type":"commit"}}"#,
                ))
                .unwrap();
        });

        unsafe {
            env::set_var(GITHUB_API_BASE_URL_ENV, &base_url);
            env::set_var(GITHUB_TOKEN_ENV, "fixture-token");
        }
        let resolved = resolve_github_action_tags(findings).unwrap();
        unsafe {
            env::remove_var(GITHUB_API_BASE_URL_ENV);
            env::remove_var(GITHUB_TOKEN_ENV);
        }
        handle.join().unwrap();

        assert_eq!(resolved[0].decision, PolicyDecision::Allow);
        assert_eq!(
            resolved[0].coordinate.version.as_deref(),
            Some("a81bbbf8298c0fa03ea29cdc473d45769f953675")
        );
    }

    #[test]
    fn scan_github_actions_skips_local_and_docker_actions() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: ./.github/actions/my-local-action\n      \
             - uses: docker://alpine:3.14\n",
        )
        .unwrap();

        let findings = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_github_actions_deduplicates_same_action_across_files() {
        let dir = tempdir().unwrap();
        let sha = "a81bbbf8298c0fa03ea29cdc473d45769f953675";
        fs::write(
            dir.path().join("ci.yml"),
            format!("name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n"),
        )
        .unwrap();
        fs::write(
            dir.path().join("release.yml"),
            format!("name: Release\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n"),
        )
        .unwrap();

        let findings = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn scan_github_actions_handles_action_with_subdirectory() {
        let dir = tempdir().unwrap();
        // Format: owner/repo/path@ref
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: owner/monorepo/subaction@v2\n",
        )
        .unwrap();

        let findings = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].coordinate.namespace.as_deref(), Some("owner"));
        assert_eq!(findings[0].coordinate.name, "monorepo");
        assert_eq!(findings[0].decision, PolicyDecision::AllowWithWarning);
    }

    #[test]
    fn scan_github_actions_errors_on_missing_dir() {
        let dir = tempdir().unwrap();
        let nonexistent = dir.path().join("nonexistent");
        let err = parse_github_actions_dir(&nonexistent).unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn scan_github_actions_errors_on_empty_dir() {
        let dir = tempdir().unwrap();
        let err = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap_err();
        assert!(format!("{err}").contains("no workflow files"));
    }

    #[test]
    fn scan_github_actions_reads_yaml_extension_files() {
        let dir = tempdir().unwrap();
        // Use .yaml extension (not .yml) to verify the glob covers both
        let sha = "a81bbbf8298c0fa03ea29cdc473d45769f953675";
        fs::write(
            dir.path().join("ci.yaml"),
            format!("name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n"),
        )
        .unwrap();

        let findings = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].decision, PolicyDecision::Allow);
    }

    #[test]
    fn scan_github_actions_errors_on_malformed_workflow_yaml() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("bad.yml"),
            // Intentionally invalid YAML (tab character where spaces expected)
            "name: CI\njobs:\n\t build:\n",
        )
        .unwrap();

        let err = parse_github_actions_dir(&dir.path().to_path_buf()).unwrap_err();
        assert!(
            format!("{err:#}").contains("parsing workflow YAML"),
            "expected YAML parse error context, got: {err:#}"
        );
    }

    #[test]
    fn scan_github_actions_command_exits_zero_on_all_allowed() {
        let dir = tempdir().unwrap();
        let sha = "a81bbbf8298c0fa03ea29cdc473d45769f953675";
        fs::write(
            dir.path().join("ci.yml"),
            format!("name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n"),
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("github-actions"),
            OsString::from("--workflow-dir"),
            dir.path().as_os_str().to_os_string(),
        ])
        .unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn scan_github_actions_command_resolve_tags_exits_zero_after_resolution() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .unwrap();

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", server.server_addr());
        let handle = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            request
                .respond(tiny_http::Response::from_string(
                    r#"{"object":{"sha":"a81bbbf8298c0fa03ea29cdc473d45769f953675","type":"commit"}}"#,
                ))
                .unwrap();
        });

        unsafe {
            env::set_var(GITHUB_API_BASE_URL_ENV, &base_url);
        }
        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("github-actions"),
            OsString::from("--workflow-dir"),
            dir.path().as_os_str().to_os_string(),
            OsString::from("--resolve-tags"),
            OsString::from("--fail-on"),
            OsString::from("warn"),
        ])
        .unwrap();
        unsafe {
            env::remove_var(GITHUB_API_BASE_URL_ENV);
        }
        handle.join().unwrap();

        assert_eq!(exit_code, 0);
    }

    #[test]
    fn scan_github_actions_command_exits_one_on_mutable_tag_with_fail_on_warn() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: actions/checkout@v4\n",
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("github-actions"),
            OsString::from("--workflow-dir"),
            dir.path().as_os_str().to_os_string(),
            OsString::from("--fail-on"),
            OsString::from("warn"),
        ])
        .unwrap();

        assert_eq!(exit_code, 1);
    }

    #[test]
    fn scan_github_actions_mutable_tag_passes_with_fail_on_block() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: actions/checkout@v4\n",
        )
        .unwrap();

        let exit_code = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("github-actions"),
            OsString::from("--workflow-dir"),
            dir.path().as_os_str().to_os_string(),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();

        // AllowWithWarning is not blocking — exit 0 with default fail-on block
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn scan_github_actions_uses_github_actions_enrichment_route() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let tenant_id = Uuid::now_v7();
        let policy_profile_id = Uuid::now_v7();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("gha-token".to_owned()),
            tenant_id: Some(tenant_id),
            policy_profile_id: Some(policy_profile_id),
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains("POST /v1/cli/github-actions/enrich HTTP/1.1"));
                assert!(request.contains("\"ecosystem\":\"githubactions\""));
                assert!(request.contains("\"namespace\":\"actions\""));
                assert!(request.contains("\"name\":\"checkout\""));
                assert!(request.contains(&format!("\"tenant_id\":\"{tenant_id}\"")));
                assert!(request.contains(&format!(
                    "\"policy_profile_id\":\"{policy_profile_id}\""
                )));
                assert!(request.contains("authorization: Bearer gha-token"));

                let response = serde_json::json!({
                    "tenant_id": "018f4a6f-55d0-7000-8000-000000000001",
                    "policy_profile_id": "018f4a6f-55d0-7000-8000-000000000101",
                    "findings": [{
                        "coordinate": {
                            "ecosystem": "githubactions",
                            "name": "checkout",
                            "version": "v4",
                            "namespace": "actions"
                        },
                        "decision": "BLOCK_KNOWN_MALICIOUS",
                        "trace_id": "cli-trace-1",
                        "rationale": ["fixture block"],
                        "create_analysis_job": false
                    }]
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
            OsString::from("scan"),
            OsString::from("github-actions"),
            OsString::from("--workflow-dir"),
            dir.path().as_os_str().to_os_string(),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();

        assert_eq!(exit_code, 1);

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn scan_github_actions_requires_explicit_policy_profile_for_remote_enrichment() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .unwrap();

        save_cli_config(&CliConfig {
            api_url: "http://127.0.0.1:9".to_owned(),
            token: Some("gha-token".to_owned()),
            tenant_id: None,
            policy_profile_id: None,
        })
        .unwrap();

        let error = run([
            OsString::from("aedo"),
            OsString::from("scan"),
            OsString::from("github-actions"),
            OsString::from("--workflow-dir"),
            dir.path().as_os_str().to_os_string(),
        ])
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("requires an explicit policy profile"));

        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn scan_github_actions_flags_override_saved_policy_context() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let saved_tenant_id = Uuid::now_v7();
        let saved_policy_profile_id = Uuid::now_v7();
        let override_tenant_id = Uuid::now_v7();
        let override_policy_profile_id = Uuid::now_v7();
        unsafe {
            env::set_var(CONFIG_OVERRIDE_ENV, dir.path());
        }
        fs::write(
            dir.path().join("ci.yml"),
            "name: CI\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        save_cli_config(&CliConfig {
            api_url: format!("http://{address}"),
            token: Some("gha-token".to_owned()),
            tenant_id: Some(saved_tenant_id),
            policy_profile_id: Some(saved_policy_profile_id),
        })
        .unwrap();

        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);
                assert!(request.contains(&format!("\"tenant_id\":\"{override_tenant_id}\"")));
                assert!(!request.contains(&format!("\"tenant_id\":\"{saved_tenant_id}\"")));
                assert!(request.contains(&format!(
                    "\"policy_profile_id\":\"{override_policy_profile_id}\""
                )));
                assert!(!request.contains(&format!(
                    "\"policy_profile_id\":\"{saved_policy_profile_id}\""
                )));

                let response = serde_json::json!({
                    "tenant_id": override_tenant_id,
                    "policy_profile_id": override_policy_profile_id,
                    "findings": [{
                        "coordinate": {
                            "ecosystem": "githubactions",
                            "name": "checkout",
                            "version": "v4",
                            "namespace": "actions"
                        },
                        "decision": "BLOCK_KNOWN_MALICIOUS",
                        "trace_id": "cli-trace-override",
                        "rationale": ["fixture block"],
                        "create_analysis_job": false
                    }]
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
            OsString::from("scan"),
            OsString::from("github-actions"),
            OsString::from("--workflow-dir"),
            dir.path().as_os_str().to_os_string(),
            OsString::from("--tenant-id"),
            OsString::from(override_tenant_id.to_string()),
            OsString::from("--policy-profile-id"),
            OsString::from(override_policy_profile_id.to_string()),
            OsString::from("--fail-on"),
            OsString::from("block"),
        ])
        .unwrap();

        assert_eq!(exit_code, 1);

        server.join().unwrap();
        unsafe {
            env::remove_var(CONFIG_OVERRIDE_ENV);
        }
    }

    #[test]
    fn is_sha_pinned_validates_40_hex_chars() {
        assert!(is_sha_pinned("a81bbbf8298c0fa03ea29cdc473d45769f953675"));
        assert!(is_sha_pinned("0000000000000000000000000000000000000000"));
        assert!(!is_sha_pinned("v4"));
        assert!(!is_sha_pinned("main"));
        assert!(!is_sha_pinned("a81bbbf8298c0fa03ea29cdc473d45769f95367")); // 39 chars
        assert!(!is_sha_pinned("a81bbbf8298c0fa03ea29cdc473d45769f9536755")); // 41 chars
        assert!(!is_sha_pinned("g81bbbf8298c0fa03ea29cdc473d45769f953675")); // non-hex char
    }
}
