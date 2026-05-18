use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const CRA_REPORT_TYPE: &str = "eu-cra-supply-chain-risk";
const SSDF_REPORT_TYPE: &str = "nist-ssdf-mapping";
const COMPLIANCE_EVIDENCE_MAX_BYTES: u64 = 1_048_576;

#[derive(Debug, Subcommand)]
pub(crate) enum ComplianceCommand {
    Cra(ComplianceReportArgs),
    Ssdf(ComplianceReportArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ComplianceReportArgs {
    /// JSON evidence bundle containing risk, SBOM, audit, and SLSA mapping inputs.
    #[arg(long)]
    evidence_file: PathBuf,
    #[arg(long, value_enum, default_value_t = ComplianceOutputFormat::Json)]
    output_format: ComplianceOutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub(crate) enum ComplianceOutputFormat {
    Text,
    Json,
}

pub(crate) fn run_compliance(command: ComplianceCommand) -> anyhow::Result<i32> {
    match command {
        ComplianceCommand::Cra(args) => {
            let bundle = load_evidence_bundle(&args.evidence_file)?;
            let report = build_cra_report(bundle);
            print_cra_report(&report, args.output_format)?;
        }
        ComplianceCommand::Ssdf(args) => {
            let bundle = load_evidence_bundle(&args.evidence_file)?;
            let report = build_ssdf_report(bundle);
            print_ssdf_report(&report, args.output_format)?;
        }
    }
    Ok(0)
}

fn load_evidence_bundle(path: &PathBuf) -> anyhow::Result<ComplianceEvidenceBundle> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading compliance evidence metadata {}", path.display()))?;
    if metadata.len() > COMPLIANCE_EVIDENCE_MAX_BYTES {
        anyhow::bail!(
            "compliance evidence bundle {} exceeds {} bytes",
            path.display(),
            COMPLIANCE_EVIDENCE_MAX_BYTES
        );
    }
    let bytes = fs::read(path)
        .with_context(|| format!("reading compliance evidence bundle {}", path.display()))?;
    let bundle: ComplianceEvidenceBundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing compliance evidence bundle {}", path.display()))?;
    bundle.validate()?;
    Ok(bundle)
}

fn build_cra_report(bundle: ComplianceEvidenceBundle) -> CraComplianceReport {
    let open_items = compliance_open_items(&bundle);
    CraComplianceReport {
        report_type: CRA_REPORT_TYPE.to_owned(),
        tenant_id: bundle.tenant_id,
        generated_at: bundle.generated_at,
        period: bundle.period,
        supply_chain_risk_management: bundle.risk_management_evidence,
        sbom_references: bundle.sbom_references,
        audit_log_summary: bundle.audit_log_summary,
        slsa_consumer_requirements: bundle.slsa_consumer_requirements,
        policy_decision_counts: bundle.policy_decision_counts,
        open_items,
    }
}

fn build_ssdf_report(bundle: ComplianceEvidenceBundle) -> SsdfComplianceReport {
    let mappings = vec![
        SsdfControlMapping {
            control_id: "PO.1".to_owned(),
            title: "Define security requirements for software development".to_owned(),
            status: evidence_status(!bundle.risk_management_evidence.is_empty()),
            evidence_refs: bundle
                .risk_management_evidence
                .iter()
                .map(|item| item.evidence_ref.clone())
                .collect(),
        },
        SsdfControlMapping {
            control_id: "PS.3".to_owned(),
            title: "Archive and protect software release evidence".to_owned(),
            status: evidence_status(!bundle.sbom_references.is_empty()),
            evidence_refs: bundle
                .sbom_references
                .iter()
                .map(|item| item.uri.clone())
                .collect(),
        },
        SsdfControlMapping {
            control_id: "RV.1".to_owned(),
            title: "Identify and confirm vulnerabilities on an ongoing basis".to_owned(),
            status: evidence_status(audit_summary_has_risk_signal(&bundle.audit_log_summary)),
            evidence_refs: bundle
                .audit_log_summary
                .iter()
                .filter(|item| audit_action_is_risk_signal(&item.action))
                .map(|item| item.action.clone())
                .collect(),
        },
        SsdfControlMapping {
            control_id: "PW.4".to_owned(),
            title: "Reuse trusted third-party software with risk checks".to_owned(),
            status: evidence_status(!bundle.slsa_consumer_requirements.is_empty()),
            evidence_refs: bundle
                .slsa_consumer_requirements
                .iter()
                .map(|item| item.requirement.clone())
                .collect(),
        },
    ];

    SsdfComplianceReport {
        report_type: SSDF_REPORT_TYPE.to_owned(),
        tenant_id: bundle.tenant_id,
        generated_at: bundle.generated_at,
        period: bundle.period,
        mappings,
        policy_decision_counts: bundle.policy_decision_counts,
    }
}

fn compliance_open_items(bundle: &ComplianceEvidenceBundle) -> Vec<String> {
    let mut open_items = Vec::new();
    if bundle.tenant_id.is_none() {
        open_items.push("Tenant scope is missing.".to_owned());
    }
    if bundle.period.is_none() {
        open_items.push("Report period is missing.".to_owned());
    }
    if bundle.policy_decision_counts.is_empty() {
        open_items.push("Policy decision counts are missing.".to_owned());
    }
    if bundle.risk_management_evidence.is_empty() {
        open_items.push("Supply chain risk management evidence is missing.".to_owned());
    }
    if bundle.sbom_references.is_empty() {
        open_items.push("SBOM references are missing.".to_owned());
    }
    if bundle.audit_log_summary.is_empty() {
        open_items.push("Audit log summary is missing.".to_owned());
    }
    if bundle.slsa_consumer_requirements.is_empty() {
        open_items.push("SLSA consumer requirement mapping is missing.".to_owned());
    }
    open_items
}

fn audit_summary_has_risk_signal(items: &[AuditLogSummary]) -> bool {
    items
        .iter()
        .any(|item| audit_action_is_risk_signal(&item.action))
}

fn audit_action_is_risk_signal(action: &str) -> bool {
    let normalized = action.to_ascii_lowercase();
    normalized.contains("vulnerab")
        || normalized.contains("risk")
        || normalized.contains("malware")
        || normalized.contains("quarantine")
        || normalized.contains("policy.decision.block")
}

fn evidence_status(has_evidence: bool) -> String {
    if has_evidence {
        "evidence-provided".to_owned()
    } else {
        "evidence-missing".to_owned()
    }
}

fn print_cra_report(
    report: &CraComplianceReport,
    format: ComplianceOutputFormat,
) -> anyhow::Result<()> {
    match format {
        ComplianceOutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        ComplianceOutputFormat::Text => {
            for line in cra_report_lines(report) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

fn print_ssdf_report(
    report: &SsdfComplianceReport,
    format: ComplianceOutputFormat,
) -> anyhow::Result<()> {
    match format {
        ComplianceOutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        ComplianceOutputFormat::Text => {
            for line in ssdf_report_lines(report) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

fn cra_report_lines(report: &CraComplianceReport) -> Vec<String> {
    let mut lines = vec![
        format!("CRA compliance report: {}", report.report_type),
        format!("generated_at: {}", report.generated_at),
        format!(
            "tenant: {}",
            report
                .tenant_id
                .map(|tenant_id| tenant_id.to_string())
                .unwrap_or_else(|| "missing".to_owned())
        ),
        format!(
            "period: {}",
            report
                .period
                .as_ref()
                .map(|period| format!("{} to {}", period.start, period.end))
                .unwrap_or_else(|| "missing".to_owned())
        ),
        format!(
            "risk evidence: {} | SBOM refs: {} | audit actions: {} | SLSA mappings: {}",
            report.supply_chain_risk_management.len(),
            report.sbom_references.len(),
            report.audit_log_summary.len(),
            report.slsa_consumer_requirements.len()
        ),
        format!("policy decisions: {}", report.policy_decision_counts.len()),
        format!("open items: {}", report.open_items.len()),
    ];
    lines.extend(report.open_items.iter().map(|item| format!("- {item}")));
    lines
}

fn ssdf_report_lines(report: &SsdfComplianceReport) -> Vec<String> {
    let mut lines = vec![
        format!("NIST SSDF report: {}", report.report_type),
        format!("generated_at: {}", report.generated_at),
    ];
    lines.extend(report.mappings.iter().map(|mapping| {
        format!(
            "{} {}: {}",
            mapping.control_id, mapping.title, mapping.status
        )
    }));
    lines
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ComplianceEvidenceBundle {
    tenant_id: Option<Uuid>,
    generated_at: String,
    #[serde(default)]
    period: Option<ReportPeriod>,
    #[serde(default)]
    risk_management_evidence: Vec<RiskManagementEvidence>,
    #[serde(default)]
    sbom_references: Vec<SbomReference>,
    #[serde(default)]
    audit_log_summary: Vec<AuditLogSummary>,
    #[serde(default)]
    slsa_consumer_requirements: Vec<SlsaConsumerRequirement>,
    #[serde(default)]
    policy_decision_counts: BTreeMap<String, u64>,
}

impl ComplianceEvidenceBundle {
    fn validate(&self) -> anyhow::Result<()> {
        ensure_non_empty(&self.generated_at, "generated_at")?;
        let _generated_at = parse_report_timestamp(&self.generated_at, "generated_at")?;
        if let Some(period) = &self.period {
            ensure_non_empty(&period.start, "period.start")?;
            ensure_non_empty(&period.end, "period.end")?;
            let start = parse_report_timestamp(&period.start, "period.start")?;
            let end = parse_report_timestamp(&period.end, "period.end")?;
            if start > end {
                anyhow::bail!("period.start must be before or equal to period.end");
            }
        }
        for item in &self.risk_management_evidence {
            ensure_non_empty(&item.control, "risk_management_evidence.control")?;
            ensure_non_empty(&item.evidence_ref, "risk_management_evidence.evidence_ref")?;
            ensure_non_empty(&item.status, "risk_management_evidence.status")?;
        }
        for item in &self.sbom_references {
            ensure_non_empty(&item.uri, "sbom_references.uri")?;
            ensure_non_empty(&item.format, "sbom_references.format")?;
            ensure_uri_has_no_userinfo(&item.uri, "sbom_references.uri")?;
            if let Some(digest) = &item.digest {
                ensure_sha256_digest(digest, "sbom_references.digest")?;
            }
        }
        for item in &self.audit_log_summary {
            ensure_non_empty(&item.action, "audit_log_summary.action")?;
            let first_seen = item
                .first_seen_at
                .as_deref()
                .map(|value| parse_report_timestamp(value, "audit_log_summary.first_seen_at"))
                .transpose()?;
            let last_seen = item
                .last_seen_at
                .as_deref()
                .map(|value| parse_report_timestamp(value, "audit_log_summary.last_seen_at"))
                .transpose()?;
            if matches!((first_seen, last_seen), (Some(first_seen), Some(last_seen)) if first_seen > last_seen)
            {
                anyhow::bail!(
                    "audit_log_summary.first_seen_at must be before or equal to last_seen_at"
                );
            }
        }
        for item in &self.slsa_consumer_requirements {
            ensure_non_empty(&item.requirement, "slsa_consumer_requirements.requirement")?;
            ensure_non_empty(&item.status, "slsa_consumer_requirements.status")?;
            ensure_allowed_status(
                &item.status,
                "slsa_consumer_requirements.status",
                &["met", "not-met", "unknown"],
            )?;
            if matches!(item.minimum_build_level, Some(level) if level > 3)
                || matches!(item.observed_build_level, Some(level) if level > 3)
            {
                anyhow::bail!("SLSA Build Track levels must be between 0 and 3");
            }
            if item.status == "met" {
                let Some(minimum_level) = item.minimum_build_level else {
                    anyhow::bail!("met SLSA requirements must include minimum_build_level");
                };
                let Some(observed_level) = item.observed_build_level else {
                    anyhow::bail!("met SLSA requirements must include observed_build_level");
                };
                if observed_level < minimum_level {
                    anyhow::bail!(
                        "met SLSA requirements must have observed_build_level greater than or equal to minimum_build_level"
                    );
                }
            }
        }
        Ok(())
    }
}

fn parse_report_timestamp(value: &str, field: &str) -> anyhow::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .with_context(|| format!("{field} must be an RFC3339 timestamp"))
}

fn ensure_uri_has_no_userinfo(value: &str, field: &str) -> anyhow::Result<()> {
    if let Some((_, rest)) = value.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.contains('@') {
            anyhow::bail!("{field} must not contain URL userinfo");
        }
    }
    Ok(())
}

fn ensure_sha256_digest(value: &str, field: &str) -> anyhow::Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        anyhow::bail!("{field} must use sha256:<lowercase-hex> format");
    };
    if hex.len() != 64
        || !hex
            .chars()
            .all(|character| matches!(character, 'a'..='f' | '0'..='9'))
    {
        anyhow::bail!("{field} must use sha256:<lowercase-hex> format");
    }
    Ok(())
}

fn ensure_allowed_status(value: &str, field: &str, allowed: &[&str]) -> anyhow::Result<()> {
    if !allowed.contains(&value) {
        anyhow::bail!("{field} must be one of {}", allowed.join(", "));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, field: &str) -> anyhow::Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!("{field} must not be empty");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReportPeriod {
    start: String,
    end: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RiskManagementEvidence {
    control: String,
    evidence_ref: String,
    status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SbomReference {
    uri: String,
    format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuditLogSummary {
    action: String,
    count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_seen_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_seen_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SlsaConsumerRequirement {
    requirement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minimum_build_level: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_build_level: Option<u8>,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence_ref: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CraComplianceReport {
    report_type: String,
    tenant_id: Option<Uuid>,
    generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    period: Option<ReportPeriod>,
    supply_chain_risk_management: Vec<RiskManagementEvidence>,
    sbom_references: Vec<SbomReference>,
    audit_log_summary: Vec<AuditLogSummary>,
    slsa_consumer_requirements: Vec<SlsaConsumerRequirement>,
    policy_decision_counts: BTreeMap<String, u64>,
    open_items: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SsdfComplianceReport {
    report_type: String,
    tenant_id: Option<Uuid>,
    generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    period: Option<ReportPeriod>,
    mappings: Vec<SsdfControlMapping>,
    policy_decision_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SsdfControlMapping {
    control_id: String,
    title: String,
    status: String,
    evidence_refs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cra_report_includes_risk_sbom_audit_and_slsa_evidence() {
        let report = build_cra_report(sample_bundle());

        assert_eq!(report.report_type, CRA_REPORT_TYPE);
        assert_eq!(report.supply_chain_risk_management.len(), 1);
        assert_eq!(report.sbom_references[0].format, "cyclonedx-1.7");
        assert_eq!(report.audit_log_summary[0].action, "policy.decision.block");
        assert_eq!(
            report.slsa_consumer_requirements[0].minimum_build_level,
            Some(2)
        );
        assert!(report.open_items.is_empty());
    }

    #[test]
    fn cra_report_surfaces_missing_compliance_inputs_as_open_items() {
        let mut bundle = sample_bundle();
        bundle.tenant_id = None;
        bundle.sbom_references.clear();
        bundle.audit_log_summary.clear();

        let report = build_cra_report(bundle);

        assert_eq!(
            report.open_items,
            vec![
                "Tenant scope is missing.".to_owned(),
                "SBOM references are missing.".to_owned(),
                "Audit log summary is missing.".to_owned(),
            ]
        );
    }

    #[test]
    fn ssdf_report_maps_available_evidence_to_controls() {
        let report = build_ssdf_report(sample_bundle());

        assert_eq!(report.report_type, SSDF_REPORT_TYPE);
        assert_eq!(report.mappings.len(), 4);
        assert!(
            report
                .mappings
                .iter()
                .all(|mapping| mapping.status == "evidence-provided")
        );
        assert!(
            report
                .mappings
                .iter()
                .any(|mapping| mapping.control_id == "PS.3"
                    && mapping.evidence_refs == ["s3://reports/sbom.cdx.json"])
        );
    }

    #[test]
    fn compliance_evidence_rejects_invalid_slsa_build_levels() {
        let mut bundle = sample_bundle();
        bundle.slsa_consumer_requirements[0].observed_build_level = Some(4);

        assert!(bundle.validate().is_err());
    }

    #[test]
    fn compliance_evidence_rejects_invalid_and_reversed_time_ranges() {
        let mut bundle = sample_bundle();
        bundle.generated_at = "not-a-time".to_owned();
        assert!(bundle.validate().is_err());

        let mut bundle = sample_bundle();
        bundle.period = Some(ReportPeriod {
            start: "2026-05-18T00:00:00Z".to_owned(),
            end: "2026-05-01T00:00:00Z".to_owned(),
        });
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn compliance_evidence_rejects_inconsistent_slsa_met_status() {
        let mut bundle = sample_bundle();
        bundle.slsa_consumer_requirements[0].minimum_build_level = Some(3);
        bundle.slsa_consumer_requirements[0].observed_build_level = Some(2);

        assert!(bundle.validate().is_err());
    }

    #[test]
    fn compliance_evidence_rejects_malformed_sbom_digest_and_userinfo() {
        let mut bundle = sample_bundle();
        bundle.sbom_references[0].digest = Some("sha256:ABC".to_owned());
        assert!(bundle.validate().is_err());

        let mut bundle = sample_bundle();
        bundle.sbom_references[0].uri = "https://user@example.invalid/sbom.json".to_owned();
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn cra_text_report_lists_open_item_details() {
        let mut bundle = sample_bundle();
        bundle.period = None;
        let report = build_cra_report(bundle);
        let lines = cra_report_lines(&report);

        assert!(lines.contains(&"period: missing".to_owned()));
        assert!(lines.contains(&"- Report period is missing.".to_owned()));
    }

    fn sample_bundle() -> ComplianceEvidenceBundle {
        let mut policy_decision_counts = BTreeMap::new();
        policy_decision_counts.insert("allow".to_owned(), 42);
        policy_decision_counts.insert("block".to_owned(), 3);

        ComplianceEvidenceBundle {
            tenant_id: Some(Uuid::parse_str("018f4a6f-55d0-7000-8000-000000000001").unwrap()),
            generated_at: "2026-05-18T00:00:00Z".to_owned(),
            period: Some(ReportPeriod {
                start: "2026-05-01T00:00:00Z".to_owned(),
                end: "2026-05-18T00:00:00Z".to_owned(),
            }),
            risk_management_evidence: vec![RiskManagementEvidence {
                control: "tenant-policy-default".to_owned(),
                evidence_ref: "policy:default@2026-05-18".to_owned(),
                status: "implemented".to_owned(),
            }],
            sbom_references: vec![SbomReference {
                uri: "s3://reports/sbom.cdx.json".to_owned(),
                format: "cyclonedx-1.7".to_owned(),
                digest: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                ),
            }],
            audit_log_summary: vec![AuditLogSummary {
                action: "policy.decision.block".to_owned(),
                count: 3,
                first_seen_at: Some("2026-05-01T00:00:00Z".to_owned()),
                last_seen_at: Some("2026-05-18T00:00:00Z".to_owned()),
            }],
            slsa_consumer_requirements: vec![SlsaConsumerRequirement {
                requirement: "SLSA Build Level 2 or higher for release artifacts".to_owned(),
                minimum_build_level: Some(2),
                observed_build_level: Some(3),
                status: "met".to_owned(),
                evidence_ref: Some("attestation:slsa-vsa:widget".to_owned()),
            }],
            policy_decision_counts,
        }
    }
}
