use aegiscudo_core::{
    ArtifactDigest, FeedState, PackageCoordinate, PackageEcosystem, PolicyDecision, PolicyMode,
};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NormalizationError {
    #[error("package name is empty")]
    EmptyName,
    #[error("package path contains traversal or absolute path segments")]
    UnsafePath,
    #[error("scoped npm packages must be formatted as @scope/name")]
    InvalidScopedPackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PackageRequestKind {
    Metadata,
    Artifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NormalizedPackageRequest {
    pub kind: PackageRequestKind,
    pub tenant_id: Uuid,
    pub registry_config_id: Uuid,
    pub policy_profile_id: Uuid,
    pub coordinate: PackageCoordinate,
    pub trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_digest: Option<ArtifactDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default)]
    pub explicit_version_or_integrity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DecisionRequest {
    pub tenant_id: Uuid,
    pub registry_config_id: Uuid,
    pub policy_profile_id: Uuid,
    pub request: NormalizedPackageRequest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecisionResponse {
    pub decision: PolicyDecision,
    pub tenant_id: Uuid,
    pub policy_profile_id: Uuid,
    pub policy_snapshot_id: Uuid,
    pub mode: PolicyMode,
    pub feed_state: FeedState,
    pub feed_snapshot_age_seconds: u64,
    pub trace_id: String,
    pub rationale: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_coordinate: Option<PackageCoordinate>,
    #[serde(default)]
    pub create_analysis_job: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdvisoryHeaderPayload {
    pub decision: PolicyDecision,
    pub trace_id: String,
    pub message: String,
}

impl AdvisoryHeaderPayload {
    pub fn to_header_value(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

pub fn normalize_npm_name(raw_path: &str) -> Result<PackageCoordinate, NormalizationError> {
    let trimmed = raw_path.trim_matches('/');
    reject_unsafe_path(trimmed)?;
    if trimmed.is_empty() {
        return Err(NormalizationError::EmptyName);
    }
    let decoded = trimmed
        .replace("%40", "@")
        .replace("%2f", "/")
        .replace("%2F", "/");
    if decoded.starts_with('@') {
        let mut parts = decoded.split('/');
        let scope = parts
            .next()
            .ok_or(NormalizationError::InvalidScopedPackage)?;
        let name = parts
            .next()
            .ok_or(NormalizationError::InvalidScopedPackage)?;
        if parts.next().is_some() || scope.len() <= 1 || name.is_empty() {
            return Err(NormalizationError::InvalidScopedPackage);
        }
        Ok(PackageCoordinate::new(
            PackageEcosystem::Npm,
            name,
            None::<String>,
            Some(scope.trim_start_matches('@')),
        ))
    } else if decoded.contains('/') {
        Err(NormalizationError::InvalidScopedPackage)
    } else {
        Ok(PackageCoordinate::new(
            PackageEcosystem::Npm,
            decoded,
            None::<String>,
            None::<String>,
        ))
    }
}

pub fn canonicalize_pypi_name(raw_name: &str) -> Result<String, NormalizationError> {
    let trimmed = raw_name.trim().trim_matches('/');
    reject_unsafe_path(trimmed)?;
    if trimmed.is_empty() {
        return Err(NormalizationError::EmptyName);
    }
    let mut canonical = String::new();
    let mut previous_separator = false;
    for character in trimmed.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !previous_separator {
                canonical.push('-');
                previous_separator = true;
            }
        } else {
            canonical.push(character.to_ascii_lowercase());
            previous_separator = false;
        }
    }
    Ok(canonical.trim_matches('-').to_owned())
}

pub fn pypi_coordinate(
    raw_name: &str,
    version: Option<&str>,
) -> Result<PackageCoordinate, NormalizationError> {
    Ok(PackageCoordinate::new(
        PackageEcosystem::Pypi,
        canonicalize_pypi_name(raw_name)?,
        version.map(str::to_owned),
        None::<String>,
    ))
}

pub fn request_timestamp() -> DateTime<Utc> {
    Utc::now()
}

fn reject_unsafe_path(value: &str) -> Result<(), NormalizationError> {
    if value.starts_with('/')
        || value
            .split('/')
            .any(|segment| matches!(segment, ".." | "." | ""))
        || value.contains('\\')
    {
        return Err(NormalizationError::UnsafePath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_npm_scoped_names() {
        let coordinate = normalize_npm_name("/@scope/pkg").unwrap();
        assert_eq!(coordinate.ecosystem, PackageEcosystem::Npm);
        assert_eq!(coordinate.namespace.as_deref(), Some("scope"));
        assert_eq!(coordinate.name, "pkg");
    }

    #[test]
    fn rejects_npm_path_traversal() {
        assert_eq!(
            normalize_npm_name("../left-pad").unwrap_err(),
            NormalizationError::UnsafePath
        );
    }

    #[test]
    fn canonicalizes_pypi_names() {
        assert_eq!(
            canonicalize_pypi_name("Requests_OAuth.Lib").unwrap(),
            "requests-oauth-lib"
        );
    }

    #[test]
    fn advisory_header_serializes_as_json() {
        let payload = AdvisoryHeaderPayload {
            decision: PolicyDecision::AllowWithWarning,
            trace_id: "trace-1".to_owned(),
            message: "warning".to_owned(),
        };
        assert!(
            payload
                .to_header_value()
                .unwrap()
                .contains("ALLOW_WITH_WARNING")
        );
    }
}
