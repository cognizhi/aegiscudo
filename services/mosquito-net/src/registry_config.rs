use std::sync::RwLock;
use std::{collections::HashSet, sync::Arc};

use aegiscudo_core::PolicyMode;
use serde::Serialize;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryAdapter {
    Npm,
    Pypi,
    Cargo,
    Maven,
    DockerOci,
    GenericHttp,
}

impl RegistryAdapter {
    pub fn is_proxy_supported(self) -> bool {
        matches!(
            self,
            Self::Npm | Self::Pypi | Self::Cargo | Self::Maven | Self::GenericHttp
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialAuthType {
    None,
    Basic,
    Bearer,
    Mtls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub adapter: RegistryAdapter,
    pub upstream_url: String,
    pub cargo_allowed_download_origins: Vec<String>,
    pub mount_path: String,
    pub auth_type: CredentialAuthType,
    pub credential_ref: Option<Uuid>,
    pub credential_env_var: Option<String>,
    pub mode: PolicyMode,
    pub policy_profile_id: Uuid,
    pub cache_ttl_seconds: i32,
    pub verify_upstream_tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRegistryConfig {
    pub config: RegistryConfig,
    pub upstream_path: String,
}

#[derive(Debug, Error)]
pub enum RegistryConfigError {
    #[error("registry adapter is invalid")]
    InvalidAdapter,
    #[error("registry auth type is invalid")]
    InvalidAuthType,
    #[error("registry auth type and credential reference are inconsistent")]
    InvalidCredentialConfiguration,
    #[error("registry enforcement mode is invalid")]
    InvalidMode,
    #[error("registry mount path is invalid or ambiguous")]
    InvalidMountPath,
    #[error("registry mount path is duplicated across loaded configurations")]
    DuplicateMountPath,
    #[error("registry upstream URL is invalid")]
    InvalidUpstreamUrl,
    #[error("Cargo allowed download origin is invalid")]
    InvalidCargoAllowedDownloadOrigin,
    #[error("authenticated upstream URLs must use https")]
    InsecureAuthenticatedUpstream,
    #[error("registry configuration repository is unavailable")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone)]
pub struct RegistryConfigStore {
    configs: Arc<RwLock<Vec<RegistryConfig>>>,
}

impl Default for RegistryConfigStore {
    fn default() -> Self {
        Self {
            configs: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl RegistryConfigStore {
    pub fn new(configs: Vec<RegistryConfig>) -> Result<Self, RegistryConfigError> {
        let configs = validate_and_sort_configs(configs)?;
        Ok(Self {
            configs: Arc::new(RwLock::new(configs)),
        })
    }

    pub fn replace_configs(&self, configs: Vec<RegistryConfig>) -> Result<(), RegistryConfigError> {
        let configs = validate_and_sort_configs(configs)?;
        *self
            .configs
            .write()
            .expect("registry config store lock should not be poisoned") = configs;
        Ok(())
    }

    pub fn resolve(&self, proxy_path: &str) -> Option<ResolvedRegistryConfig> {
        let normalized_proxy_path = proxy_path.trim_matches('/');
        self.configs
            .read()
            .expect("registry config store lock should not be poisoned")
            .iter()
            .find_map(|config| {
                let mount = normalized_mount(&config.mount_path).ok()?;
                if normalized_proxy_path == mount {
                    return Some(ResolvedRegistryConfig {
                        config: config.clone(),
                        upstream_path: String::new(),
                    });
                }
                normalized_proxy_path
                    .strip_prefix(&format!("{mount}/"))
                    .map(|upstream_path| ResolvedRegistryConfig {
                        config: config.clone(),
                        upstream_path: upstream_path.to_owned(),
                    })
            })
    }

    pub fn len(&self) -> usize {
        self.configs
            .read()
            .expect("registry config store lock should not be poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.configs
            .read()
            .expect("registry config store lock should not be poisoned")
            .is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct PostgresRegistryConfigRepository {
    pool: PgPool,
}

impl PostgresRegistryConfigRepository {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn load_enabled(&self) -> Result<RegistryConfigStore, RegistryConfigError> {
        RegistryConfigStore::new(self.load_enabled_configs().await?)
    }

    pub async fn load_enabled_configs(&self) -> Result<Vec<RegistryConfig>, RegistryConfigError> {
        let rows = sqlx::query(
            r#"
            SELECT
                            registry_configs.id,
                            registry_configs.tenant_id,
                            registry_configs.name,
                            registry_configs.adapter::text AS adapter,
                            registry_configs.upstream_url,
                            registry_configs.cargo_allowed_download_origins,
                            registry_configs.mount_path,
                            registry_configs.auth_type::text AS auth_type,
                            registry_configs.credential_ref,
              credential.name AS credential_env_var,
                            registry_configs.mode::text AS mode,
                            registry_configs.policy_profile_id,
                            registry_configs.cache_ttl_seconds,
                            registry_configs.verify_upstream_tls
            FROM registry_configs
                        LEFT JOIN integration_credentials credential
                            ON credential.tenant_id = registry_configs.tenant_id
                         AND credential.id = registry_configs.credential_ref
                        WHERE registry_configs.enabled = true AND registry_configs.deleted_at IS NULL
                        ORDER BY length(registry_configs.mount_path) DESC, registry_configs.mount_path ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let configs = rows
            .iter()
            .map(registry_config_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(configs)
    }
}

fn validate_and_sort_configs(
    mut configs: Vec<RegistryConfig>,
) -> Result<Vec<RegistryConfig>, RegistryConfigError> {
    let mut seen_mounts = HashSet::new();
    for config in &mut configs {
        normalize_registry_config(config)?;
        let mount = normalized_mount(&config.mount_path)?;
        if !seen_mounts.insert(mount) {
            return Err(RegistryConfigError::DuplicateMountPath);
        }
    }
    configs.sort_by_key(|config| {
        std::cmp::Reverse(normalized_mount(&config.mount_path).map_or(0, |mount| mount.len()))
    });
    Ok(configs)
}

fn registry_config_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RegistryConfig, RegistryConfigError> {
    Ok(RegistryConfig {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        adapter: adapter_from_db(row.try_get("adapter")?)?,
        upstream_url: row.try_get("upstream_url")?,
        cargo_allowed_download_origins: row.try_get("cargo_allowed_download_origins")?,
        mount_path: row.try_get("mount_path")?,
        auth_type: auth_type_from_db(row.try_get("auth_type")?)?,
        credential_ref: row.try_get("credential_ref")?,
        credential_env_var: row.try_get("credential_env_var")?,
        mode: mode_from_db(row.try_get("mode")?)?,
        policy_profile_id: row.try_get("policy_profile_id")?,
        cache_ttl_seconds: row.try_get("cache_ttl_seconds")?,
        verify_upstream_tls: row.try_get("verify_upstream_tls")?,
    })
}

fn adapter_from_db(value: String) -> Result<RegistryAdapter, RegistryConfigError> {
    match value.as_str() {
        "npm" => Ok(RegistryAdapter::Npm),
        "pypi" => Ok(RegistryAdapter::Pypi),
        "cargo" => Ok(RegistryAdapter::Cargo),
        "maven" => Ok(RegistryAdapter::Maven),
        "docker-oci" => Ok(RegistryAdapter::DockerOci),
        "generic-http" => Ok(RegistryAdapter::GenericHttp),
        _ => Err(RegistryConfigError::InvalidAdapter),
    }
}

fn auth_type_from_db(value: String) -> Result<CredentialAuthType, RegistryConfigError> {
    match value.as_str() {
        "none" => Ok(CredentialAuthType::None),
        "basic" => Ok(CredentialAuthType::Basic),
        "bearer" => Ok(CredentialAuthType::Bearer),
        "mtls" => Ok(CredentialAuthType::Mtls),
        _ => Err(RegistryConfigError::InvalidAuthType),
    }
}

fn mode_from_db(value: String) -> Result<PolicyMode, RegistryConfigError> {
    match value.as_str() {
        "shadow" => Ok(PolicyMode::Shadow),
        "warn" => Ok(PolicyMode::Warn),
        "enforce" => Ok(PolicyMode::Enforce),
        _ => Err(RegistryConfigError::InvalidMode),
    }
}

fn normalized_mount(mount_path: &str) -> Result<String, RegistryConfigError> {
    let trimmed = mount_path.trim();
    if !trimmed.starts_with('/') || trimmed.ends_with('/') || trimmed.contains("//") {
        return Err(RegistryConfigError::InvalidMountPath);
    }
    let without_slashes = trimmed.trim_start_matches('/');
    let effective = without_slashes
        .strip_prefix("proxy/")
        .unwrap_or(without_slashes);
    if effective.is_empty()
        || effective.split('/').any(|segment| {
            segment.is_empty()
                || !segment.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
        })
    {
        return Err(RegistryConfigError::InvalidMountPath);
    }
    Ok(effective.to_owned())
}

fn normalize_registry_config(config: &mut RegistryConfig) -> Result<(), RegistryConfigError> {
    validate_upstream_url(&config.upstream_url, config.auth_type)?;
    validate_credential_configuration(config.auth_type, config.credential_ref)?;
    let mut normalized_origins = Vec::with_capacity(config.cargo_allowed_download_origins.len());
    let mut seen_origins = HashSet::new();
    for origin in &config.cargo_allowed_download_origins {
        let normalized = normalize_allowed_origin(origin)?;
        if seen_origins.insert(normalized.clone()) {
            normalized_origins.push(normalized);
        }
    }
    config.cargo_allowed_download_origins = normalized_origins;
    Ok(())
}

fn normalize_allowed_origin(origin: &str) -> Result<String, RegistryConfigError> {
    let parsed =
        Url::parse(origin).map_err(|_| RegistryConfigError::InvalidCargoAllowedDownloadOrigin)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(RegistryConfigError::InvalidCargoAllowedDownloadOrigin);
    }

    let host = parsed
        .host_str()
        .ok_or(RegistryConfigError::InvalidCargoAllowedDownloadOrigin)?;
    let mut normalized = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        normalized.push(':');
        normalized.push_str(&port.to_string());
    }
    Ok(normalized)
}

fn validate_upstream_url(
    upstream_url: &str,
    auth_type: CredentialAuthType,
) -> Result<(), RegistryConfigError> {
    let parsed = Url::parse(upstream_url).map_err(|_| RegistryConfigError::InvalidUpstreamUrl)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(RegistryConfigError::InvalidUpstreamUrl);
    }
    if parsed.scheme() == "http" && auth_type != CredentialAuthType::None {
        return Err(RegistryConfigError::InsecureAuthenticatedUpstream);
    }
    Ok(())
}

fn validate_credential_configuration(
    auth_type: CredentialAuthType,
    credential_ref: Option<Uuid>,
) -> Result<(), RegistryConfigError> {
    match (auth_type, credential_ref) {
        (CredentialAuthType::None, None)
        | (
            CredentialAuthType::Basic | CredentialAuthType::Bearer | CredentialAuthType::Mtls,
            Some(_),
        ) => Ok(()),
        _ => Err(RegistryConfigError::InvalidCredentialConfiguration),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mount_path: &str, adapter: RegistryAdapter) -> RegistryConfig {
        RegistryConfig {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            name: mount_path.trim_matches('/').to_owned(),
            adapter,
            upstream_url: "https://registry.example.invalid".to_owned(),
            cargo_allowed_download_origins: Vec::new(),
            mount_path: mount_path.to_owned(),
            auth_type: CredentialAuthType::None,
            credential_ref: None,
            credential_env_var: None,
            mode: PolicyMode::Enforce,
            policy_profile_id: Uuid::now_v7(),
            cache_ttl_seconds: 300,
            verify_upstream_tls: true,
        }
    }

    #[test]
    fn resolves_configured_mount_and_upstream_path() {
        let store =
            RegistryConfigStore::new(vec![config("/proxy/npm-public", RegistryAdapter::Npm)])
                .expect("valid store");
        let resolved = store
            .resolve("npm-public/@scope/name")
            .expect("mount should resolve");

        assert_eq!(resolved.config.adapter, RegistryAdapter::Npm);
        assert_eq!(resolved.upstream_path, "@scope/name");
    }

    #[test]
    fn prefers_longest_mount_prefix() {
        let store = RegistryConfigStore::new(vec![
            config("/proxy/team", RegistryAdapter::Npm),
            config("/proxy/team/pypi", RegistryAdapter::Pypi),
        ])
        .expect("valid store");
        let resolved = store
            .resolve("team/pypi/simple/Requests")
            .expect("nested mount should resolve");

        assert_eq!(resolved.config.adapter, RegistryAdapter::Pypi);
        assert_eq!(resolved.upstream_path, "simple/Requests");
    }

    #[test]
    fn rejects_duplicate_effective_mounts_until_tenant_routing_exists() {
        let result = RegistryConfigStore::new(vec![
            config("/proxy/npm-public", RegistryAdapter::Npm),
            config("/npm-public", RegistryAdapter::Pypi),
        ]);

        assert!(matches!(
            result,
            Err(RegistryConfigError::DuplicateMountPath)
        ));
    }

    #[test]
    fn rejects_upstream_urls_with_embedded_credentials() {
        let mut config = config("/proxy/npm-public", RegistryAdapter::Npm);
        config.upstream_url = "https://user:pass@registry.example.invalid".to_owned();

        let result = RegistryConfigStore::new(vec![config]);

        assert!(matches!(
            result,
            Err(RegistryConfigError::InvalidUpstreamUrl)
        ));
    }

    #[test]
    fn rejects_authenticated_http_upstreams() {
        let mut config = config("/proxy/npm-private", RegistryAdapter::Npm);
        config.upstream_url = "http://registry.example.invalid".to_owned();
        config.auth_type = CredentialAuthType::Bearer;
        config.credential_ref = Some(Uuid::now_v7());

        let result = RegistryConfigStore::new(vec![config]);

        assert!(matches!(
            result,
            Err(RegistryConfigError::InsecureAuthenticatedUpstream)
        ));
    }

    #[test]
    fn normalizes_cargo_allowed_download_origins() {
        let mut cargo = config("/proxy/cargo-public", RegistryAdapter::Cargo);
        cargo.cargo_allowed_download_origins = vec![
            "https://static.example.invalid/".to_owned(),
            "https://static.example.invalid".to_owned(),
            "http://127.0.0.1:8443/".to_owned(),
        ];

        let store = RegistryConfigStore::new(vec![cargo]).expect("valid store");
        let configs = store
            .configs
            .read()
            .expect("registry config store lock should not be poisoned")
            .clone();

        assert_eq!(
            configs[0].cargo_allowed_download_origins,
            vec![
                "https://static.example.invalid".to_owned(),
                "http://127.0.0.1:8443".to_owned(),
            ]
        );
    }

    #[test]
    fn rejects_invalid_cargo_allowed_download_origin() {
        let mut cargo = config("/proxy/cargo-public", RegistryAdapter::Cargo);
        cargo.cargo_allowed_download_origins =
            vec!["https://static.example.invalid/path".to_owned()];

        let result = RegistryConfigStore::new(vec![cargo]);

        assert!(matches!(
            result,
            Err(RegistryConfigError::InvalidCargoAllowedDownloadOrigin)
        ));
    }

    #[test]
    fn rejects_missing_credential_reference_for_authenticated_upstream() {
        let mut config = config("/proxy/npm-private", RegistryAdapter::Npm);
        config.auth_type = CredentialAuthType::Bearer;

        let result = RegistryConfigStore::new(vec![config]);

        assert!(matches!(
            result,
            Err(RegistryConfigError::InvalidCredentialConfiguration)
        ));
    }

    #[test]
    fn rejects_unexpected_credential_reference_for_unauthenticated_upstream() {
        let mut config = config("/proxy/npm-public", RegistryAdapter::Npm);
        config.credential_ref = Some(Uuid::now_v7());

        let result = RegistryConfigStore::new(vec![config]);

        assert!(matches!(
            result,
            Err(RegistryConfigError::InvalidCredentialConfiguration)
        ));
    }
}
