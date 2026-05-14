ALTER TABLE registry_configs
  ADD COLUMN IF NOT EXISTS cargo_allowed_download_origins text[] NOT NULL DEFAULT ARRAY[]::text[];
