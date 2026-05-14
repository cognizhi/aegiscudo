import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

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

const cargoEvidence: ArtifactEvidence = {
  ...baseEvidence,
  artifact_id: "artifact-cargo-1",
  trace_id: "trace-cargo-1",
  coordinate: { ecosystem: "cargo", name: "cargo-evil", version: "0.1.0" },
  static_reports: [
    {
      artifact_digest: { algorithm: "sha256", hex: "2222222222222222222222222222222222222222222222222222222222222222" },
      analyzer_version: "fixture-static-1.0.0",
      rule_set_version: "fixture-rules-2026.05.05",
      indicators: [
        {
          indicator_type: "cargo-build-script",
          severity: "critical",
          file_path: "build.rs",
          start_line: 1,
          end_line: 12,
          redacted: false,
          summary: "build.rs performs a network bootstrap during compilation",
        },
        {
          indicator_type: "cargo-proc-macro",
          severity: "high",
          file_path: "Cargo.toml",
          start_line: 6,
          end_line: 6,
          redacted: false,
          summary: "crate exposes a proc-macro target",
        },
        {
          indicator_type: "cargo-git-dependency",
          severity: "high",
          file_path: "Cargo.toml",
          start_line: 14,
          end_line: 16,
          redacted: false,
          summary: "dependency resolves from a Git source",
        },
        {
          indicator_type: "cargo-patch-override",
          severity: "high",
          file_path: "Cargo.toml",
          start_line: 18,
          end_line: 21,
          redacted: false,
          summary: "manifest overrides a registry dependency via patch",
        },
        {
          indicator_type: "rust-raw-network",
          severity: "critical",
          file_path: "src/lib.rs",
          start_line: 3,
          end_line: 9,
          redacted: false,
          summary: "crate opens a raw TCP socket",
        },
        {
          indicator_type: "bundled-native-artifact",
          severity: "high",
          file_path: "vendor/libpayload.so",
          start_line: 1,
          end_line: 1,
          redacted: false,
          summary: "precompiled native payload shipped in the crate",
        },
      ],
    },
  ],
};

const cargoItem: QuarantineQueueItem = {
  ...baseItem,
  artifact_id: "artifact-cargo-1",
  trace_id: "trace-cargo-1",
  coordinate: { ecosystem: "cargo", name: "cargo-evil", version: "0.1.0" },
};

const mavenEvidence: ArtifactEvidence = {
  ...baseEvidence,
  artifact_id: "artifact-maven-1",
  trace_id: "trace-maven-1",
  coordinate: { ecosystem: "maven", namespace: "com.acme", name: "evil-jar", version: "1.0.0" },
  static_reports: [
    {
      artifact_digest: { algorithm: "sha256", hex: "6666666666666666666666666666666666666666666666666666666666666666" },
      analyzer_version: "fixture-static-1.0.0",
      rule_set_version: "fixture-rules-2026.05.05",
      indicators: [
        {
          indicator_type: "java-outbound-http",
          severity: "high",
          file_path: "evil.jar!/com/acme/Bootstrap.class",
          start_line: 1,
          end_line: 1,
          redacted: false,
          summary: "bytecode opens an outbound HTTP connection",
        },
        {
          indicator_type: "java-env-read",
          severity: "high",
          file_path: "evil.jar!/com/acme/Secrets.class",
          start_line: 1,
          end_line: 1,
          redacted: false,
          summary: "bytecode reads environment variables",
        },
        {
          indicator_type: "java-static-init",
          severity: "high",
          file_path: "evil.jar!/com/acme/Bootstrap.class",
          start_line: 1,
          end_line: 1,
          redacted: false,
          summary: "static initializer executes during class load",
        },
        {
          indicator_type: "zip-path-traversal",
          severity: "critical",
          file_path: "evil.jar!/../../../etc/passwd",
          start_line: 1,
          end_line: 1,
          redacted: false,
          summary: "archive entry attempts path traversal during extraction",
        },
        {
          indicator_type: "bundled-native-artifact",
          severity: "high",
          file_path: "evil.jar!/libsigar.so",
          start_line: 1,
          end_line: 1,
          redacted: false,
          summary: "jar ships a bundled precompiled native library",
        },
      ],
    },
  ],
};

const mavenItem: QuarantineQueueItem = {
  ...baseItem,
  artifact_id: "artifact-maven-1",
  trace_id: "trace-maven-1",
  coordinate: { ecosystem: "maven", namespace: "com.acme", name: "evil-jar", version: "1.0.0" },
};

afterEach(() => {
  delete process.env.NEXT_PUBLIC_LANGFUSE_BASE_URL;
});

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

  it("replaces queued summary metadata when detailed evidence loads", () => {
    const { rerender } = render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={undefined}
        isLoading
        item={{
          ...baseItem,
          recommended_action: "QUARANTINE_PENDING_ANALYSIS",
          confidence: "low",
          requires_hitl: true,
          summary: {
            evidence: {
              static_indicator_count: 1,
              sandbox_event_count: 4,
              malware_match_count: 2,
            },
            limitations: ["Queued snapshot limitation"],
            ai_observed_behavior: ["Queued snapshot behavior"],
            ai_inference: ["Queued snapshot inference"],
          },
        }}
      />,
    );

    expect(screen.getByTestId("artifact-chip-recommended-action")).toHaveTextContent("QUARANTINE_PENDING_ANALYSIS");
    expect(screen.getByTestId("artifact-chip-confidence")).toHaveTextContent("Confidence low");
    expect(screen.getByTestId("artifact-chip-hitl")).toHaveTextContent("Requires HITL");
    expect(screen.getByTestId("artifact-trace-id")).toHaveTextContent("Trace trace-1");
    expect(screen.getByText("Queued snapshot limitation")).toBeInTheDocument();
    expect(screen.getByText("Queued snapshot behavior")).toBeInTheDocument();
    expect(screen.getByText("Queued snapshot inference")).toBeInTheDocument();

    rerender(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...baseEvidence,
          trace_id: "trace-detail-1",
          recommended_action: "BLOCK_POLICY_VIOLATION",
          confidence: "high",
          requires_hitl: false,
          summary: {
            evidence: {
              static_indicator_count: 5,
              sandbox_event_count: 0,
              malware_match_count: 0,
            },
            limitations: ["Detailed evidence limitation"],
            ai_observed_behavior: ["Detailed observed behavior"],
            ai_inference: ["Detailed inference"],
          },
        }}
        isLoading={false}
        item={{
          ...baseItem,
          recommended_action: "QUARANTINE_PENDING_ANALYSIS",
          confidence: "low",
          requires_hitl: true,
          summary: {
            evidence: {
              static_indicator_count: 1,
              sandbox_event_count: 4,
              malware_match_count: 2,
            },
            limitations: ["Queued snapshot limitation"],
            ai_observed_behavior: ["Queued snapshot behavior"],
            ai_inference: ["Queued snapshot inference"],
          },
        }}
      />,
    );

    expect(screen.getByTestId("artifact-summary-static-indicators")).toHaveTextContent("5");
    expect(screen.getByTestId("artifact-summary-sandbox-events")).toHaveTextContent("0");
    expect(screen.getByTestId("artifact-summary-malware-matches")).toHaveTextContent("0");
    expect(screen.getByTestId("artifact-chip-recommended-action")).toHaveTextContent("BLOCK_POLICY_VIOLATION");
    expect(screen.getByTestId("artifact-chip-confidence")).toHaveTextContent("Confidence high");
    expect(screen.getByTestId("artifact-chip-hitl")).toHaveTextContent("Automated outcome");
    expect(screen.getByTestId("artifact-trace-id")).toHaveTextContent("Trace trace-detail-1");
    expect(screen.getByText("Detailed evidence limitation")).toBeInTheDocument();
    expect(screen.getByText("Detailed observed behavior")).toBeInTheDocument();
    expect(screen.getByText("Detailed inference")).toBeInTheDocument();
    expect(screen.queryByText("Queued snapshot limitation")).not.toBeInTheDocument();
    expect(screen.queryByText("Queued snapshot behavior")).not.toBeInTheDocument();
    expect(screen.queryByText("Queued snapshot inference")).not.toBeInTheDocument();
  });

  it("resets the active tab when the selected artifact changes", () => {
    const { rerender } = render(
      <ArtifactEvidenceViewer
        key="artifact-1"
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
        key="artifact-2"
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

    rerender(
      <ArtifactEvidenceViewer
        key="artifact-1-return"
        errorMessage={null}
        evidence={baseEvidence}
        isLoading={false}
        item={baseItem}
      />,
    );

    expect(screen.getByText("Files")).toBeInTheDocument();
    expect(screen.queryByText("Phase")).not.toBeInTheDocument();
  });

  it("falls back to queued summary fields when detailed evidence is partial", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...baseEvidence,
          summary: {
            evidence: {
              static_indicator_count: 5,
            },
          },
        }}
        isLoading={false}
        item={baseItem}
      />,
    );

    expect(screen.getByTestId("artifact-summary-static-indicators")).toHaveTextContent("5");
    expect(screen.getByTestId("artifact-summary-sandbox-events")).toHaveTextContent("2");
    expect(screen.getByTestId("artifact-summary-malware-matches")).toHaveTextContent("0");
    expect(screen.getByText("sandbox telemetry still requires human review")).toBeInTheDocument();
    expect(screen.getByText("Observed runtime network attempt")).toBeInTheDocument();
    expect(screen.getByText("Package likely boots a remote installer")).toBeInTheDocument();
  });

  it("renders a cargo build profile panel when cargo static indicators are present", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={cargoEvidence}
        isLoading={false}
        item={cargoItem}
      />,
    );

    expect(screen.getByTestId("artifact-cargo-panel")).toBeInTheDocument();
    expect(screen.getByTestId("artifact-cargo-summary-build-execution-value")).toHaveTextContent(/^2$/);
    expect(screen.getByTestId("artifact-cargo-summary-source-overrides-value")).toHaveTextContent(/^2$/);
    expect(screen.getByTestId("artifact-cargo-summary-dependency-expansion-value")).toHaveTextContent(/^0$/);
    expect(screen.getByTestId("artifact-cargo-summary-native-surface-value")).toHaveTextContent(/^1$/);
    expect(screen.getByTestId("artifact-cargo-summary-runtime-access-value")).toHaveTextContent(/^1$/);
    expect(
      screen.getByText("Build execution (2 findings): cargo-build-script, cargo-proc-macro"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Source overrides (2 findings): cargo-git-dependency, cargo-patch-override"),
    ).toBeInTheDocument();
    expect(screen.getByText("Native surface (1 finding): bundled-native-artifact")).toBeInTheDocument();
    expect(screen.getAllByText("build.rs").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Cargo.toml").length).toBeGreaterThan(0);
    expect(screen.getAllByText("src/lib.rs").length).toBeGreaterThan(0);
    expect(screen.getAllByText("vendor/libpayload.so").length).toBeGreaterThan(0);
  });

  it("keeps the cargo panel visible when cargo static reports have no mapped cargo signals", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...cargoEvidence,
          static_reports: [
            {
              artifact_digest: {
                algorithm: "sha256",
                hex: "3333333333333333333333333333333333333333333333333333333333333333",
              },
              analyzer_version: "fixture-static-1.0.0",
              rule_set_version: "fixture-rules-2026.05.05",
              indicators: [
                {
                  indicator_type: "high-entropy-string",
                  severity: "medium",
                  file_path: "src/lib.rs",
                  start_line: 4,
                  end_line: 4,
                  redacted: false,
                  summary: "encoded blob embedded in source",
                },
              ],
            },
          ],
        }}
        isLoading={false}
        item={cargoItem}
      />,
    );

    expect(screen.getByTestId("artifact-cargo-panel")).toBeInTheDocument();
    expect(screen.getByTestId("artifact-cargo-summary-build-execution-value")).toHaveTextContent(/^0$/);
    expect(screen.getByTestId("artifact-cargo-summary-native-surface-value")).toHaveTextContent(/^0$/);
    expect(screen.getByText("No Cargo-specific build signals were captured.")).toBeInTheDocument();
    expect(screen.getByText("No Cargo-specific files were flagged.")).toBeInTheDocument();
  });

  it("labels cargo signal rows with finding counts when one type appears multiple times", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...cargoEvidence,
          static_reports: [
            {
              artifact_digest: {
                algorithm: "sha256",
                hex: "4444444444444444444444444444444444444444444444444444444444444444",
              },
              analyzer_version: "fixture-static-1.0.0",
              rule_set_version: "fixture-rules-2026.05.05",
              indicators: [
                {
                  indicator_type: "cargo-build-script",
                  severity: "high",
                  file_path: "Cargo.toml",
                  start_line: 5,
                  end_line: 5,
                  redacted: false,
                  summary: "build script declared for pre-compilation execution",
                },
                {
                  indicator_type: "cargo-build-script",
                  severity: "high",
                  file_path: "build.rs",
                  start_line: 1,
                  end_line: 10,
                  redacted: false,
                  summary: "build script contains executable logic",
                },
              ],
            },
          ],
        }}
        isLoading={false}
        item={cargoItem}
      />,
    );

    expect(screen.getByTestId("artifact-cargo-summary-build-execution-value")).toHaveTextContent(/^2$/);
    expect(screen.getByText("Build execution (2 findings): cargo-build-script")).toBeInTheDocument();
  });

  it("maps each cargo indicator type into the expected cargo summary bucket", () => {
    const cases = [
      ["cargo-build-script", "artifact-cargo-summary-build-execution-value"],
      ["cargo-proc-macro", "artifact-cargo-summary-build-execution-value"],
      ["cargo-git-dependency", "artifact-cargo-summary-source-overrides-value"],
      ["cargo-path-dependency", "artifact-cargo-summary-source-overrides-value"],
      ["cargo-alternate-registry-dependency", "artifact-cargo-summary-source-overrides-value"],
      ["cargo-patch-override", "artifact-cargo-summary-source-overrides-value"],
      ["cargo-replace-override", "artifact-cargo-summary-source-overrides-value"],
      ["cargo-build-dependency", "artifact-cargo-summary-dependency-expansion-value"],
      ["cargo-dev-dependency", "artifact-cargo-summary-dependency-expansion-value"],
      ["cargo-target-specific-dependency", "artifact-cargo-summary-dependency-expansion-value"],
      ["cargo-optional-dependency", "artifact-cargo-summary-dependency-expansion-value"],
      ["cargo-feature-graph", "artifact-cargo-summary-dependency-expansion-value"],
      ["vendored-native-code", "artifact-cargo-summary-native-surface-value"],
      ["bundled-native-artifact", "artifact-cargo-summary-native-surface-value"],
      ["rust-raw-network", "artifact-cargo-summary-runtime-access-value"],
      ["rust-env-read", "artifact-cargo-summary-runtime-access-value"],
    ] as const;

    for (const [indicatorType, expectedBucketTestId] of cases) {
      const { unmount } = render(
        <ArtifactEvidenceViewer
          errorMessage={null}
          evidence={{
            ...cargoEvidence,
            static_reports: [
              {
                artifact_digest: {
                  algorithm: "sha256",
                  hex: "5555555555555555555555555555555555555555555555555555555555555555",
                },
                analyzer_version: "fixture-static-1.0.0",
                rule_set_version: "fixture-rules-2026.05.05",
                indicators: [
                  {
                    indicator_type: indicatorType,
                    severity: "high",
                    file_path: "Cargo.toml",
                    start_line: 1,
                    end_line: 1,
                    redacted: false,
                    summary: `${indicatorType} summary`,
                  },
                ],
              },
            ],
          }}
          isLoading={false}
          item={cargoItem}
        />,
      );

      expect(screen.getByTestId(expectedBucketTestId)).toHaveTextContent(/^1$/);
      unmount();
    }
  });

  it("renders a JVM binary profile panel when maven static indicators are present", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={mavenEvidence}
        isLoading={false}
        item={mavenItem}
      />,
    );

    expect(screen.getByTestId("artifact-jvm-panel")).toBeInTheDocument();
    expect(screen.getByTestId("artifact-jvm-summary-network-surface-value")).toHaveTextContent(/^1$/);
    expect(screen.getByTestId("artifact-jvm-summary-environment-access-value")).toHaveTextContent(/^1$/);
    expect(screen.getByTestId("artifact-jvm-summary-early-execution-value")).toHaveTextContent(/^1$/);
    expect(screen.getByTestId("artifact-jvm-summary-archive-safety-value")).toHaveTextContent(/^1$/);
    expect(screen.getByTestId("artifact-jvm-summary-native-surface-value")).toHaveTextContent(/^1$/);
    expect(screen.getByText("Network surface (1 finding): java-outbound-http")).toBeInTheDocument();
    expect(screen.getByText("Environment access (1 finding): java-env-read")).toBeInTheDocument();
    expect(screen.getByText("Early execution (1 finding): java-static-init")).toBeInTheDocument();
    expect(screen.getByText("Archive safety (1 finding): zip-path-traversal")).toBeInTheDocument();
    expect(screen.getByText("Native surface (1 finding): bundled-native-artifact")).toBeInTheDocument();
    expect(screen.getAllByText("evil.jar!/com/acme/Bootstrap.class").length).toBeGreaterThan(0);
    expect(screen.getAllByText("evil.jar!/com/acme/Secrets.class").length).toBeGreaterThan(0);
    expect(screen.getAllByText("evil.jar!/../../../etc/passwd").length).toBeGreaterThan(0);
    expect(screen.getAllByText("evil.jar!/libsigar.so").length).toBeGreaterThan(0);
  });

  it("keeps the JVM panel visible when maven static reports have no mapped JVM signals", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...mavenEvidence,
          static_reports: [
            {
              artifact_digest: {
                algorithm: "sha256",
                hex: "7777777777777777777777777777777777777777777777777777777777777777",
              },
              analyzer_version: "fixture-static-1.0.0",
              rule_set_version: "fixture-rules-2026.05.05",
              indicators: [
                {
                  indicator_type: "high-entropy-string",
                  severity: "medium",
                  file_path: "src/Main.java",
                  start_line: 4,
                  end_line: 4,
                  redacted: false,
                  summary: "encoded blob embedded in bytecode resources",
                },
              ],
            },
          ],
        }}
        isLoading={false}
        item={mavenItem}
      />,
    );

    expect(screen.getByTestId("artifact-jvm-panel")).toBeInTheDocument();
    expect(screen.getByTestId("artifact-jvm-summary-network-surface-value")).toHaveTextContent(/^0$/);
    expect(screen.getByTestId("artifact-jvm-summary-native-surface-value")).toHaveTextContent(/^0$/);
    expect(screen.getByText("No JVM-specific binary signals were captured.")).toBeInTheDocument();
    expect(screen.getByText("No JVM-specific files were flagged.")).toBeInTheDocument();
  });

  it("keeps the JVM panel visible when a maven artifact has no static reports yet", () => {
    render(
      <ArtifactEvidenceViewer
        errorMessage={null}
        evidence={{
          ...mavenEvidence,
          static_reports: [],
        }}
        isLoading={false}
        item={mavenItem}
      />,
    );

    expect(screen.getByTestId("artifact-jvm-panel")).toBeInTheDocument();
    expect(screen.getByTestId("artifact-jvm-summary-network-surface-value")).toHaveTextContent(/^0$/);
    expect(screen.getByTestId("artifact-jvm-summary-native-surface-value")).toHaveTextContent(/^0$/);
    expect(screen.getByText("No static analysis reports are available.")).toBeInTheDocument();
    expect(screen.getByText("No static analysis files are available.")).toBeInTheDocument();
  });

  it("maps each JVM indicator type into the expected JVM summary bucket", () => {
    const cases = [
      ["java-outbound-http", "artifact-jvm-summary-network-surface-value"],
      ["java-env-read", "artifact-jvm-summary-environment-access-value"],
      ["java-static-init", "artifact-jvm-summary-early-execution-value"],
      ["zip-path-traversal", "artifact-jvm-summary-archive-safety-value"],
      ["vendored-native-code", "artifact-jvm-summary-native-surface-value"],
      ["bundled-native-artifact", "artifact-jvm-summary-native-surface-value"],
    ] as const;

    for (const [indicatorType, expectedBucketTestId] of cases) {
      const { unmount } = render(
        <ArtifactEvidenceViewer
          errorMessage={null}
          evidence={{
            ...mavenEvidence,
            static_reports: [
              {
                artifact_digest: {
                  algorithm: "sha256",
                  hex: "8888888888888888888888888888888888888888888888888888888888888888",
                },
                analyzer_version: "fixture-static-1.0.0",
                rule_set_version: "fixture-rules-2026.05.05",
                indicators: [
                  {
                    indicator_type: indicatorType,
                    severity: "high",
                    file_path: "evil.jar!/com/acme/Fixture.class",
                    start_line: 1,
                    end_line: 1,
                    redacted: false,
                    summary: `${indicatorType} summary`,
                  },
                ],
              },
            ],
          }}
          isLoading={false}
          item={mavenItem}
        />,
      );

      expect(screen.getByTestId(expectedBucketTestId)).toHaveTextContent(/^1$/);
      unmount();
    }
  });
});