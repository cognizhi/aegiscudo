import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";
const baselineArtifactId = "018f4a6f-55d0-7000-8000-000000000700";
const cargoArtifactId = "018f4a6f-55d0-7000-8000-000000000701";

const mockBaselineQueueItem = {
  analysis_job_id: "018f4a6f-55d0-7000-8000-000000000600",
  artifact_id: baselineArtifactId,
  trace_id: "trace-npm-000",
  coordinate: { ecosystem: "npm", name: "prefilled-risk", version: "1.2.3" },
  artifact_sha256: "b".repeat(64),
  recommended_action: "BLOCK_POLICY_VIOLATION",
  confidence: "medium",
  requires_hitl: false,
  created_at: "2026-05-14T12:10:00Z",
  evidence_counts: {
    static_reports: 0,
    sandbox_runs: 0,
    ai_explanations: 0,
    audit_events: 0,
  },
  summary: {
    recommended_action: "BLOCK_POLICY_VIOLATION",
    confidence: "medium",
    requires_hitl: false,
    evidence: {
      static_indicator_count: 0,
      sandbox_event_count: 0,
      malware_match_count: 0,
    },
    limitations: ["No additional evidence captured."],
    ai_observed_behavior: [],
    ai_inference: [],
  },
};

const mockCargoQueueItem = {
  analysis_job_id: "018f4a6f-55d0-7000-8000-000000000601",
  artifact_id: cargoArtifactId,
  trace_id: "trace-cargo-001",
  coordinate: { ecosystem: "cargo", name: "cargo-evil", version: "0.1.0" },
  artifact_sha256: "c".repeat(64),
  recommended_action: "QUARANTINE_PENDING_ANALYSIS",
  confidence: "low",
  requires_hitl: true,
  created_at: "2026-05-14T12:15:00Z",
  evidence_counts: {
    static_reports: 1,
    sandbox_runs: 0,
    ai_explanations: 1,
    audit_events: 1,
  },
  summary: {
    recommended_action: "QUARANTINE_PENDING_ANALYSIS",
    confidence: "high",
    requires_hitl: true,
    evidence: {
      static_indicator_count: 1,
      sandbox_event_count: 4,
      malware_match_count: 2,
    },
    limitations: ["Queued snapshot still awaits detailed evidence."],
    ai_observed_behavior: ["Queued snapshot placeholder behavior."],
    ai_inference: ["Queued snapshot placeholder inference."],
  },
};

const mockCargoEvidence = {
  analysis_job_id: mockCargoQueueItem.analysis_job_id,
  artifact_id: cargoArtifactId,
  trace_id: "trace-cargo-detail-001",
  coordinate: mockCargoQueueItem.coordinate,
  artifact_sha256: mockCargoQueueItem.artifact_sha256,
  recommended_action: "BLOCK_POLICY_VIOLATION",
  confidence: "high",
  requires_hitl: false,
  summary: {
    recommended_action: "BLOCK_POLICY_VIOLATION",
    confidence: "high",
    requires_hitl: false,
    evidence: {
      static_indicator_count: 6,
      sandbox_event_count: 0,
      malware_match_count: 0,
    },
    limitations: ["Sandbox evidence is missing for this artifact."],
    ai_observed_behavior: ["Cargo build script opens raw TCP socket during compilation."],
    ai_inference: ["Build-time code execution and source overrides require manual review."],
  },
  static_reports: [
    {
      artifact_digest: { algorithm: "sha256", hex: mockCargoQueueItem.artifact_sha256 },
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
          indicator_type: "cargo-proc-macro",
          severity: "medium",
          file_path: "Cargo.toml",
          start_line: 8,
          end_line: 8,
          redacted: false,
          summary: "proc-macro crate can execute compiler plugin code during builds",
        },
        {
          indicator_type: "cargo-git-dependency",
          severity: "medium",
          file_path: "Cargo.toml",
          start_line: 14,
          end_line: 16,
          redacted: false,
          summary: "git dependency bypasses crates.io registry immutability",
        },
        {
          indicator_type: "cargo-patch-override",
          severity: "medium",
          file_path: "Cargo.toml",
          start_line: 20,
          end_line: 22,
          redacted: false,
          summary: "[patch] overrides the default registry source",
        },
        {
          indicator_type: "rust-raw-network",
          severity: "high",
          file_path: "build.rs",
          start_line: 3,
          end_line: 7,
          redacted: false,
          summary: "build script opens a raw TCP socket before compile completes",
        },
        {
          indicator_type: "bundled-native-artifact",
          severity: "high",
          file_path: "vendor/libpayload.so",
          start_line: 1,
          end_line: 1,
          redacted: false,
          summary: "crate ships a bundled precompiled native library",
        },
      ],
    },
  ],
  sandbox_runs: [],
  ai_explanation: {
    advisory_only: true,
    langfuse_trace_id: "langfuse-trace-cargo-001",
  },
  audit_events: [
    {
      id: "018f4a6f-55d0-7000-8000-000000000801",
      tenant_id: tenantId,
      actor: "system/fixture-seed",
      action: "analysis.summary.completed",
      resource: `analysis-job/${mockCargoQueueItem.analysis_job_id}`,
      metadata: { ecosystem: "cargo" },
      occurred_at: "2026-05-14T12:16:00Z",
    },
  ],
};

const mockBaselineEvidence = {
  analysis_job_id: mockBaselineQueueItem.analysis_job_id,
  artifact_id: baselineArtifactId,
  trace_id: mockBaselineQueueItem.trace_id,
  coordinate: mockBaselineQueueItem.coordinate,
  artifact_sha256: mockBaselineQueueItem.artifact_sha256,
  recommended_action: mockBaselineQueueItem.recommended_action,
  confidence: mockBaselineQueueItem.confidence,
  requires_hitl: mockBaselineQueueItem.requires_hitl,
  summary: mockBaselineQueueItem.summary,
  static_reports: [],
  sandbox_runs: [],
  ai_explanation: null,
  audit_events: [],
};

async function openShell(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible({
    timeout: 30_000,
  });
}

test.describe("Overview: Cargo Evidence", () => {
  test("renders cargo static evidence through persona-backed routes", async ({ page }) => {
    let queueActorHeader: string | undefined;
    let baselineEvidenceActorHeader: string | undefined;
    let cargoEvidenceActorHeader: string | undefined;

    await page.route(`**/api/tenants/${tenantId}/analysis/quarantine-queue`, async (route) => {
      queueActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: [mockBaselineQueueItem, mockCargoQueueItem] });
    });

    await page.route(`**/api/tenants/${tenantId}/artifacts/${baselineArtifactId}/evidence`, async (route) => {
      baselineEvidenceActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockBaselineEvidence });
    });

    await page.route(`**/api/tenants/${tenantId}/artifacts/${cargoArtifactId}/evidence`, async (route) => {
      cargoEvidenceActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockCargoEvidence });
    });

    await openShell(page);

    const baselineRow = page.getByRole("row", {
      name: /pkg:npm\/prefilled-risk@1\.2\.3/,
    });
    await expect(baselineRow).toBeVisible();
    await baselineRow.click();
    await expect.poll(() => baselineEvidenceActorHeader).toBe(platformAdminActorId);
    await expect(page.getByRole("heading", { name: "pkg:npm/prefilled-risk@1.2.3" })).toBeVisible();

    const cargoRow = page.getByRole("row", {
      name: /pkg:cargo\/cargo-evil@0\.1\.0/,
    });
    await expect(cargoRow).toBeVisible();
    await expect(cargoRow).toContainText("QUARANTINE_PENDING_ANALYSIS");
    await expect.poll(() => queueActorHeader).toBe(platformAdminActorId);

    await cargoRow.click();
    await expect.poll(() => cargoEvidenceActorHeader).toBe(platformAdminActorId);

    await expect(page.getByText("Artifact Evidence Viewer")).toBeVisible();
    await expect(page.getByRole("heading", { name: "pkg:cargo/cargo-evil@0.1.0" })).toBeVisible();
    await expect(page.getByTestId("artifact-chip-recommended-action")).toContainText("BLOCK_POLICY_VIOLATION");
    await expect(page.getByTestId("artifact-chip-confidence")).toContainText("Confidence high");
    await expect(page.getByTestId("artifact-chip-hitl")).toContainText("Automated outcome");
    await expect(page.getByTestId("artifact-trace-id")).toContainText("Trace trace-cargo-detail-001");
    await expect(page.getByTestId("artifact-summary-static-indicators")).toContainText("6");
    await expect(page.getByTestId("artifact-summary-sandbox-events")).toContainText("0");
    await expect(page.getByTestId("artifact-summary-malware-matches")).toContainText("0");
    await expect(page.getByText("Sandbox evidence is missing for this artifact.")).toBeVisible();
    await expect(
      page.getByText("Cargo build script opens raw TCP socket during compilation."),
    ).toBeVisible();
    await expect(
      page.getByText("Build-time code execution and source overrides require manual review."),
    ).toBeVisible();
    await expect(page.getByText("Queued snapshot placeholder behavior.")).toHaveCount(0);
    await expect(page.getByText("Queued snapshot placeholder inference.")).toHaveCount(0);

    await page.getByRole("button", { name: "Static Analysis" }).click();
    const cargoPanel = page.getByTestId("artifact-cargo-panel");
    const filesCard = page.getByTestId("artifact-static-files");
    const staticReportCard = page.getByTestId("artifact-static-report-1");
    await expect(cargoPanel).toBeVisible();
    await expect(page.getByTestId("artifact-cargo-summary-build-execution-value")).toHaveText("2");
    await expect(page.getByTestId("artifact-cargo-summary-source-overrides-value")).toHaveText("2");
    await expect(page.getByTestId("artifact-cargo-summary-dependency-expansion-value")).toHaveText("0");
    await expect(page.getByTestId("artifact-cargo-summary-native-surface-value")).toHaveText("1");
    await expect(page.getByTestId("artifact-cargo-summary-runtime-access-value")).toHaveText("1");
    await expect(
      cargoPanel.getByText("Build execution (2 findings): cargo-build-script, cargo-proc-macro"),
    ).toBeVisible();
    await expect(
      cargoPanel.getByText("Source overrides (2 findings): cargo-git-dependency, cargo-patch-override"),
    ).toBeVisible();
    await expect(cargoPanel.getByText("Native surface (1 finding): bundled-native-artifact")).toBeVisible();
    await expect(cargoPanel.getByText("build.rs", { exact: true })).toBeVisible();
    await expect(cargoPanel.getByText("Cargo.toml", { exact: true })).toBeVisible();
    await expect(cargoPanel.getByText("vendor/libpayload.so", { exact: true })).toBeVisible();
    await expect(filesCard).toBeVisible();
    await expect(filesCard.getByText("Cargo.toml", { exact: true })).toBeVisible();
    await expect(filesCard.getByText("build.rs", { exact: true })).toBeVisible();
    await expect(filesCard.getByText("vendor/libpayload.so", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("cargo-build-script", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("cargo-proc-macro", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("cargo-git-dependency", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("cargo-patch-override", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("rust-raw-network", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("bundled-native-artifact", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Sandbox Telemetry" }).click();
    await expect(page.getByText("No sandbox telemetry is available.")).toBeVisible();

    await page.getByRole("button", { name: "AI Explanation" }).click();
    const aiPanel = page.getByTestId("artifact-ai-explanation-panel");
    await expect(
      aiPanel.getByText("AI explanation is advisory only and never the sole enforcement authority."),
    ).toBeVisible();
    await expect(aiPanel.getByText("Langfuse Trace")).toBeVisible();
    await expect(aiPanel.getByText("langfuse-trace-cargo-001", { exact: true })).toBeVisible();
    await expect(aiPanel.locator("pre")).toContainText("advisory_only");

    await page.getByRole("button", { name: "Audit Trail" }).click();
    await expect(page.getByText("analysis.summary.completed")).toBeVisible();
    await expect(page.getByText(`analysis-job/${mockCargoQueueItem.analysis_job_id}`)).toBeVisible();
  });
});