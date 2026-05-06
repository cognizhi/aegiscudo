use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use aegiscudo_core::{PackageCoordinate, PackageEcosystem, PolicyDecision};
use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

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
        default_value = "http://localhost:8082"
    )]
    api_url: String,
    #[arg(long, env = "AEGISCUDO_TOKEN")]
    token: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ScanCommand {
    Npm(NpmScanArgs),
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

pub fn run(args: impl IntoIterator<Item = OsString>) -> anyhow::Result<i32> {
    match Cli::parse_from(args).command {
        Command::Auth { command } => run_auth(command),
        Command::Scan { command } => run_scan(command),
        Command::Explain(args) => {
            println!(
                "explain request prepared for {} in {:?}; API lookup wiring belongs to Phase 1C integration",
                args.package, args.ecosystem
            );
            Ok(0)
        }
        Command::Policy { command } => match command {
            PolicyCommand::Test(args) => {
                let _ = fs::read_to_string(&args.file)
                    .with_context(|| format!("reading policy file {}", args.file.display()))?;
                println!(
                    "policy file parsed for dry-run submission: {}",
                    args.file.display()
                );
                Ok(0)
            }
        },
        Command::Ci { command } => match command {
            CiCommand::Preflight(args) => {
                let report = ScanReport {
                    source: "ci-preflight-placeholder".to_owned(),
                    upload_manifest: false,
                    findings: Vec::new(),
                };
                print_report(&report, args.format)?;
                Ok(exit_code(&report.findings, args.fail_on))
            }
        },
    }
}

fn run_auth(command: AuthCommand) -> anyhow::Result<i32> {
    match command {
        AuthCommand::Login(args) => {
            if args.token.is_some() {
                println!("authenticated configuration accepted for {}", args.api_url);
            } else {
                println!(
                    "no token provided; set AEGISCUDO_TOKEN or pass --token for non-interactive login"
                );
            }
        }
        AuthCommand::Logout => println!("local auth state cleared"),
        AuthCommand::Status => println!("auth status: not configured in this scaffold"),
    }
    Ok(0)
}

fn run_scan(command: ScanCommand) -> anyhow::Result<i32> {
    match command {
        ScanCommand::Npm(args) => {
            let findings = parse_package_lock(&args.lockfile)?;
            let report = ScanReport {
                source: args.lockfile.display().to_string(),
                upload_manifest: args.upload_manifest,
                findings,
            };
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Pypi(args) => {
            let findings = parse_requirements(&args.requirements)?;
            let report = ScanReport {
                source: args.requirements.display().to_string(),
                upload_manifest: args.upload_manifest,
                findings,
            };
            print_report(&report, args.output_format)?;
            Ok(exit_code(&report.findings, args.fail_on))
        }
        ScanCommand::Cargo(_) | ScanCommand::Maven(_) | ScanCommand::Docker(_) => {
            println!("not-yet-supported: this ecosystem is phase-gated after the npm/PyPI MVP");
            Ok(3)
        }
    }
}

fn parse_package_lock(path: &PathBuf) -> anyhow::Result<Vec<ScanFinding>> {
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
    use tempfile::tempdir;

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
    fn parses_requirements() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(&path, "requests==2.32.0\n# comment\nuvicorn>=0.30\n").unwrap();
        let findings = parse_requirements(&path).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].coordinate.purl(), "pkg:pypi/requests@2.32.0");
    }
}
