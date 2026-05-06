import type { DecisionSummary } from "@aegiscudo/shared-types";

export const decisions: DecisionSummary[] = [
  {
    coordinate: { ecosystem: "npm", name: "eslint-config-safe", version: "4.2.1" },
    decision: "ALLOW",
    traceId: "trace-allow-001",
    rationale: ["Previously approved artifact digest"],
  },
  {
    coordinate: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0" },
    decision: "QUARANTINE_PENDING_ANALYSIS",
    traceId: "trace-quarantine-002",
    rationale: ["Version is younger than minimum release age", "Lifecycle script detected"],
  },
  {
    coordinate: { ecosystem: "pypi", name: "requestz", version: "99.0.0" },
    decision: "BLOCK_POLICY_VIOLATION",
    traceId: "trace-block-003",
    rationale: ["Typosquatting similarity to requests"],
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