CREATE TABLE analysis_summaries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_job_id uuid NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  artifact_id uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  recommended_action policy_decision NOT NULL,
  confidence text NOT NULL,
  requires_hitl boolean NOT NULL DEFAULT false,
  summary jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (analysis_job_id)
);

CREATE INDEX idx_analysis_summaries_artifact_created
  ON analysis_summaries (artifact_id, created_at DESC);