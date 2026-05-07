ALTER TABLE integration_credentials
  ADD CONSTRAINT integration_credentials_tenant_id_id_unique UNIQUE (tenant_id, id);

ALTER TABLE policy_profiles
  ADD CONSTRAINT policy_profiles_tenant_id_id_unique UNIQUE (tenant_id, id);

ALTER TABLE registry_configs
  ADD CONSTRAINT registry_configs_tenant_id_id_unique UNIQUE (tenant_id, id),
  ADD CONSTRAINT registry_configs_policy_profile_tenant_fk
    FOREIGN KEY (tenant_id, policy_profile_id) REFERENCES policy_profiles(tenant_id, id),
  ADD CONSTRAINT registry_configs_credential_tenant_fk
    FOREIGN KEY (tenant_id, credential_ref) REFERENCES integration_credentials(tenant_id, id),
  ADD CONSTRAINT registry_configs_mount_path_canonical
    CHECK (mount_path ~ '^/proxy/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$'),
  ADD CONSTRAINT registry_configs_upstream_url_no_userinfo
    CHECK (upstream_url !~ '^https?://[^/@]+@');

CREATE UNIQUE INDEX registry_configs_active_mount_path_global_unique
  ON registry_configs (mount_path)
  WHERE deleted_at IS NULL;

ALTER TABLE policy_versions
  ADD CONSTRAINT policy_versions_policy_profile_tenant_fk
    FOREIGN KEY (tenant_id, policy_profile_id) REFERENCES policy_profiles(tenant_id, id);

ALTER TABLE package_requests
  ADD CONSTRAINT package_requests_registry_config_tenant_fk
    FOREIGN KEY (tenant_id, registry_config_id) REFERENCES registry_configs(tenant_id, id);