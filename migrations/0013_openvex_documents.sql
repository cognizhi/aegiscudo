CREATE TABLE openvex_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source text NOT NULL,
  document_id text NOT NULL,
  author text NOT NULL,
  context text NOT NULL,
  version bigint NOT NULL,
  document_timestamp timestamptz NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now(),
  expiry_mode text NOT NULL CHECK (expiry_mode IN ('never', 'expires_at')),
  expires_at timestamptz,
  document_digest text NOT NULL CHECK (document_digest ~ '^[a-f0-9]{64}$'),
  statement_count integer NOT NULL DEFAULT 0,
  document jsonb NOT NULL,
  CHECK (
    (expiry_mode = 'never' AND expires_at IS NULL)
    OR (expiry_mode = 'expires_at' AND expires_at IS NOT NULL)
  )
);

CREATE INDEX idx_openvex_documents_tenant_imported_at
  ON openvex_documents (tenant_id, imported_at DESC);

CREATE INDEX idx_openvex_documents_tenant_document_id
  ON openvex_documents (tenant_id, document_id);

CREATE TABLE openvex_statements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  openvex_document_id uuid NOT NULL REFERENCES openvex_documents(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  statement_index integer NOT NULL,
  vulnerability_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('affected', 'fixed', 'not_affected', 'under_investigation')),
  product_id text NOT NULL,
  justification text,
  impact_statement text,
  action_statement text,
  statement_timestamp timestamptz,
  raw_statement jsonb NOT NULL,
  UNIQUE (openvex_document_id, statement_index, vulnerability_id, product_id)
);

CREATE INDEX idx_openvex_statements_tenant_lookup
  ON openvex_statements (tenant_id, vulnerability_id, product_id, status);