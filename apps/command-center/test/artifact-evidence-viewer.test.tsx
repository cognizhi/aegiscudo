import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ArtifactEvidence, QuarantineQueueItem } from "@aegiscudo/shared-types";

import { ArtifactEvidenceViewer } from "@/components/artifact-evidence-viewer";

const baseEvidence: ArtifactEvidence = {
  analysis_job_id: "job-1",
  artifact_id: "artifact-1",
  trace_id: "trace-1",
  coordinate: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0" },
  artifact_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
  recommended_action: "QUARANTINE_PENDING_ANALYSIS",
  confidence: "high",
  requires_hitl: true,
  summary: {
    evidence: {
      static_indicator_count: 2,
      sandbox_event_count: 2,
      malware_match_count: 0,
    },
    limitations: ["sandbox telemetry still requires human review"],
    ai_observed_behavior: ["Observed runtime network attempt"],
    ai_inference: ["Package likely boots a remote installer"],
  },
  static_reports: [
    {
      artifact_digest: { algorithm: "sha256", hex: "1111111111111111111111111111111111111111111111111111111111111111" },
      analyzer_version: "fixture-static-1.0.0",
      rule_set_version: "fixture-rules-2026.05.05",
      indicators: [
        {
          indicator_type: "lifecycle-script",
          severity: "high",
          file_path: "package.json",
          start_line: 12,
          end_line: 18,
          redacted: false,
          summary: "postinstall script invokes remote bootstrap",
        },
      ],
    },
  ],
  sandbox_runs: [
    {
      profile: "default",
      state: "completed",
      started_at: "2026-05-05T10:11:45Z",
      completed_at: "2026-05-05T10:12:40Z",
      telemetry: {
        phases: [
          {
            name: "runtime",
            events: [
              {
                type: "outbound-network-attempt",
                severity: "high",
                summary: "connection attempt to suspicious host",
              },
            ],
          },
        ],
      },
    },
  ],
  ai_explanation: {
    advisory_only: true,
  },
  audit_events: [],
};

const baseItem: QuarantineQueueItem = {
  analysis_job_id: "job-1",
  artifact_id: "artifact-1",
  trace_id: "trace-1",
  coordinate: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0" },
  artifact_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
  recommended_action: "QUARANTINE_PENDING_ANALYSIS",
  confidence: "high",
  requires_hitl: true,
  created_at: "2026-05-05T10:11:45Z",
  evidence_counts: {
    static_reports: 1,
    sandbox_runs: 1,
    ai_explanations: 1,
    audit_events: 0,
  },
  summary: {
    evidence: {
      static_indicator_count: 2,
      sandbox_event_count: 2,
      malware_match_count: 0,
    },
    limitations: ["sandbox telemetry still requires human review"],
    ai_observed_behavior: ["Observed runtime network attempt"],
    ai_inference: ["Package likely boots a remote installer"],
  },
};

describe("ArtifactEvidenceViewer", () => {
  it("renders a Langfuse trace link on the AI tab when trace metadata is present", () => {
    process.env.NEXT_PUBLIC_LANGFUSE_BASE_URL = "https://langfuse.example";

    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...baseEvidence,
          ai_explanation: {
            advisory_only: true,
            langfuse_trace_id: "trace-langfuse-123",
          },
        }}
        isLoading={false}
        item={baseItem}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "AI Explanation" }));

    expect(screen.getByText("Langfuse Trace")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "trace-langfuse-123" })).toHaveAttribute(
      "href",
      "https://langfuse.example/trace/trace-langfuse-123",
    );

    delete process.env.NEXT_PUBLIC_LANGFUSE_BASE_URL;
  });

  it("renders structured static analysis and sandbox evidence from seeded payloads", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={baseEvidence}
        isLoading={false}
        item={baseItem}
      />,
    );

    expect(screen.getByText("Files")).toBeInTheDocument();
    expect(screen.getAllByText("package.json").length).toBeGreaterThan(0);
    expect(screen.getAllByText("postinstall script invokes remote bootstrap").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Sandbox Telemetry" }));

    expect(screen.getByText("Phase")).toBeInTheDocument();
    expect(screen.getByText("runtime")).toBeInTheDocument();
    expect(screen.getByText("connection attempt to suspicious host")).toBeInTheDocument();
  });

  it("resets the active tab when the selected artifact changes", () => {
    const { rerender } = render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={baseEvidence}
        isLoading={false}
        item={baseItem}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Sandbox Telemetry" }));
    expect(screen.getByText("Phase")).toBeInTheDocument();

    rerender(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...baseEvidence,
          artifact_id: "artifact-2",
          trace_id: "trace-2",
        }}
        isLoading={false}
        item={{
          ...baseItem,
          artifact_id: "artifact-2",
          trace_id: "trace-2",
        }}
      />,
    );

    expect(screen.getByText("Files")).toBeInTheDocument();
    expect(screen.queryByText("Phase")).not.toBeInTheDocument();
  });
});