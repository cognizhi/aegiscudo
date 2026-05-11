import type { QuarantineQueueItem } from "@aegiscudo/shared-types";

export const quarantineQueueItems: QuarantineQueueItem[] = [
  {
    analysis_job_id: "018f4a6f-55d0-7000-8000-000000000101",
    artifact_id: "018f4a6f-55d0-7000-8000-000000000201",
    trace_id: "trace-quarantine-002",
    coordinate: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0" },
    artifact_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    recommended_action: "QUARANTINE_PENDING_ANALYSIS",
    confidence: "medium",
    requires_hitl: true,
    summary: {
      recommended_action: "QUARANTINE_PENDING_ANALYSIS",
      confidence: "medium",
      requires_hitl: true,
      evidence: {
        static_indicator_count: 2,
        sandbox_event_count: 0,
        vulnerability_count: 0,
        malware_match_count: 0,
      },
      limitations: ["Sandbox evidence is missing for this artifact."],
      ai_observed_behavior: ["Lifecycle script detected during static inspection."],
      ai_inference: ["Manual review is required before promotion."],
    },
    evidence_counts: {
      static_reports: 1,
      sandbox_runs: 0,
      ai_explanations: 1,
      audit_events: 2,
    },
    created_at: "2026-05-05T10:00:00Z",
  },
  {
    analysis_job_id: "018f4a6f-55d0-7000-8000-000000000102",
    artifact_id: "018f4a6f-55d0-7000-8000-000000000202",
    trace_id: "trace-block-003",
    coordinate: { ecosystem: "pypi", name: "requestz", version: "99.0.0" },
    artifact_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    recommended_action: "BLOCK_POLICY_VIOLATION",
    confidence: "high",
    requires_hitl: false,
    summary: {
      recommended_action: "BLOCK_POLICY_VIOLATION",
      confidence: "high",
      requires_hitl: false,
      evidence: {
        static_indicator_count: 1,
        sandbox_event_count: 2,
        vulnerability_count: 0,
        malware_match_count: 0,
      },
      limitations: [],
      ai_observed_behavior: ["Outbound network attempt observed in sandbox."],
      ai_inference: ["Typosquatting and runtime behavior indicate a policy violation."],
    },
    evidence_counts: {
      static_reports: 1,
      sandbox_runs: 1,
      ai_explanations: 1,
      audit_events: 3,
    },
    created_at: "2026-05-05T10:15:00Z",
  },
];

export const chartData = [
  { hour: "08:00", allow: 220, warn: 12, quarantine: 4, block: 1 },
  { hour: "10:00", allow: 260, warn: 10, quarantine: 7, block: 3 },
  { hour: "12:00", allow: 310, warn: 18, quarantine: 6, block: 2 },
  { hour: "14:00", allow: 280, warn: 14, quarantine: 10, block: 5 },
];

export const metrics = [
  { label: "Blocked", value: "11", tone: "critical", helper: "Packages stopped by policy in the selected range." },
  { label: "Quarantine", value: "27", tone: "warning", helper: "Artifacts waiting for analysis or review." },
  { label: "Overrides", value: "3", tone: "pending", helper: "Active time-bound exceptions." },
  { label: "Feed State", value: "Fresh", tone: "safe", helper: "Last successful normalized feed snapshots are within policy." },
] as const;