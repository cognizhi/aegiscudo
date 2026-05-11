ALTER TABLE static_analysis_reports
  ADD COLUMN report_storage_uri text,
  ADD COLUMN report_storage_sha256 text CHECK (
    report_storage_sha256 IS NULL
    OR report_storage_sha256 ~ '^[a-f0-9]{64}$'
  ),
  ADD COLUMN report_storage_size_bytes bigint CHECK (
    report_storage_size_bytes IS NULL
    OR report_storage_size_bytes >= 0
  );

ALTER TABLE static_analysis_reports
  ADD CONSTRAINT static_analysis_reports_external_storage_fields_check CHECK (
    (
      report_storage_uri IS NULL
      AND report_storage_sha256 IS NULL
      AND report_storage_size_bytes IS NULL
    )
    OR (
      report_storage_uri IS NOT NULL
      AND report_storage_sha256 IS NOT NULL
      AND report_storage_size_bytes IS NOT NULL
    )
  );

CREATE INDEX idx_static_analysis_reports_external_storage_digest
  ON static_analysis_reports (report_storage_sha256)
  WHERE report_storage_sha256 IS NOT NULL;