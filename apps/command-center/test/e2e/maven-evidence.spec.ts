import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";
const baselineArtifactId = "018f4a6f-55d0-7000-8000-000000000700";
const mavenArtifactId = "018f4a6f-55d0-7000-8000-000000000702";

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

const mockMavenQueueItem = {
  analysis_job_id: "018f4a6f-55d0-7000-8000-000000000602",
  artifact_id: mavenArtifactId,
  trace_id: "trace-maven-001",
  coordinate: { ecosystem: "maven", namespace: "com.acme", name: "evil-jar", version: "1.0.0" },
  artifact_sha256: "d".repeat(64),
  recommended_action: "QUARANTINE_PENDING_ANALYSIS",
  confidence: "low",
  requires_hitl: true,
  created_at: "2026-05-14T12:20:00Z",
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
      sandbox_event_count: 2,
      malware_match_count: 0,
    },
    limitations: ["Queued snapshot still awaits detailed JVM evidence."],
    ai_observed_behavior: ["Queued snapshot placeholder behavior."],
    ai_inference: ["Queued snapshot placeholder inference."],
  },
};

const mockMavenEvidence = {
  analysis_job_id: mockMavenQueueItem.analysis_job_id,
  artifact_id: mavenArtifactId,
  trace_id: "trace-maven-detail-001",
  coordinate: mockMavenQueueItem.coordinate,
  artifact_sha256: mockMavenQueueItem.artifact_sha256,
  recommended_action: "BLOCK_POLICY_VIOLATION",
  confidence: "high",
  requires_hitl: false,
  summary: {
    recommended_action: "BLOCK_POLICY_VIOLATION",
    confidence: "high",
    requires_hitl: false,
    evidence: {
      static_indicator_count: 5,
      sandbox_event_count: 0,
      malware_match_count: 0,
    },
    limitations: ["Sandbox evidence is missing for this artifact."],
    ai_observed_behavior: ["JAR bytecode reaches outbound network and environment access primitives."],
    ai_inference: ["Archive safety and native payload indicators require manual review."],
  },
  static_reports: [
    {
      artifact_digest: { algorithm: "sha256", hex: mockMavenQueueItem.artifact_sha256 },
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
  sandbox_runs: [],
  ai_explanation: {
    advisory_only: true,
    langfuse_trace_id: "langfuse-trace-maven-001",
  },
  audit_events: [
    {
      id: "018f4a6f-55d0-7000-8000-000000000802",
      tenant_id: tenantId,
      actor: "system/fixture-seed",
      action: "analysis.summary.completed",
      resource: `analysis-job/${mockMavenQueueItem.analysis_job_id}`,
      metadata: { ecosystem: "maven" },
      occurred_at: "2026-05-14T12:21:00Z",
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

test.describe("Overview: Maven Evidence", () => {
  test("renders JVM static evidence through persona-backed routes", async ({ page }) => {
    let queueActorHeader: string | undefined;
    let baselineEvidenceActorHeader: string | undefined;
    let mavenEvidenceActorHeader: string | undefined;

    await page.route(`**/api/tenants/${tenantId}/analysis/quarantine-queue`, async (route) => {
      queueActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: [mockBaselineQueueItem, mockMavenQueueItem] });
    });

    await page.route(`**/api/tenants/${tenantId}/artifacts/${baselineArtifactId}/evidence`, async (route) => {
      baselineEvidenceActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockBaselineEvidence });
    });

    await page.route(`**/api/tenants/${tenantId}/artifacts/${mavenArtifactId}/evidence`, async (route) => {
      mavenEvidenceActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockMavenEvidence });
    });

    await openShell(page);

    const baselineRow = page.getByRole("row", {
      name: /pkg:npm\/prefilled-risk@1\.2\.3/,
    });
    await expect(baselineRow).toBeVisible();
    await baselineRow.click();
    await expect.poll(() => baselineEvidenceActorHeader).toBe(platformAdminActorId);
    await expect(page.getByRole("heading", { name: "pkg:npm/prefilled-risk@1.2.3" })).toBeVisible();

    const mavenRow = page.getByRole("row", {
      name: /pkg:maven\/com\.acme\/evil-jar@1\.0\.0/,
    });
    await expect(mavenRow).toBeVisible();
    await expect(mavenRow).toContainText("QUARANTINE_PENDING_ANALYSIS");
    await expect.poll(() => queueActorHeader).toBe(platformAdminActorId);

    await mavenRow.click();
    await expect.poll(() => mavenEvidenceActorHeader).toBe(platformAdminActorId);

    await expect(page.getByText("Artifact Evidence Viewer")).toBeVisible();
    await expect(page.getByRole("heading", { name: "pkg:maven/com.acme/evil-jar@1.0.0" })).toBeVisible();
    await expect(page.getByTestId("artifact-chip-recommended-action")).toContainText("BLOCK_POLICY_VIOLATION");
    await expect(page.getByTestId("artifact-chip-confidence")).toContainText("Confidence high");
    await expect(page.getByTestId("artifact-chip-hitl")).toContainText("Automated outcome");
    await expect(page.getByTestId("artifact-trace-id")).toContainText("Trace trace-maven-detail-001");
    await expect(page.getByTestId("artifact-summary-static-indicators")).toContainText("5");
    await expect(page.getByText("Sandbox evidence is missing for this artifact.")).toBeVisible();
    await expect(
      page.getByText("JAR bytecode reaches outbound network and environment access primitives."),
    ).toBeVisible();
    await expect(
      page.getByText("Archive safety and native payload indicators require manual review."),
    ).toBeVisible();
    await expect(page.getByText("Queued snapshot placeholder behavior.")).toHaveCount(0);
    await expect(page.getByText("Queued snapshot placeholder inference.")).toHaveCount(0);

    await page.getByRole("button", { name: "Static Analysis" }).click();
    const jvmPanel = page.getByTestId("artifact-jvm-panel");
    const filesCard = page.getByTestId("artifact-static-files");
    const staticReportCard = page.getByTestId("artifact-static-report-1");
    await expect(jvmPanel).toBeVisible();
    await expect(page.getByTestId("artifact-jvm-summary-network-surface-value")).toHaveText("1");
    await expect(page.getByTestId("artifact-jvm-summary-environment-access-value")).toHaveText("1");
    await expect(page.getByTestId("artifact-jvm-summary-early-execution-value")).toHaveText("1");
    await expect(page.getByTestId("artifact-jvm-summary-archive-safety-value")).toHaveText("1");
    await expect(page.getByTestId("artifact-jvm-summary-native-surface-value")).toHaveText("1");
    await expect(jvmPanel.getByText("Network surface (1 finding): java-outbound-http")).toBeVisible();
    await expect(jvmPanel.getByText("Environment access (1 finding): java-env-read")).toBeVisible();
    await expect(jvmPanel.getByText("Early execution (1 finding): java-static-init")).toBeVisible();
    await expect(jvmPanel.getByText("Archive safety (1 finding): zip-path-traversal")).toBeVisible();
    await expect(jvmPanel.getByText("Native surface (1 finding): bundled-native-artifact")).toBeVisible();
    await expect(jvmPanel.getByText("evil.jar!/com/acme/Bootstrap.class", { exact: true })).toBeVisible();
    await expect(jvmPanel.getByText("evil.jar!/com/acme/Secrets.class", { exact: true })).toBeVisible();
    await expect(jvmPanel.getByText("evil.jar!/../../../etc/passwd", { exact: true })).toBeVisible();
    await expect(jvmPanel.getByText("evil.jar!/libsigar.so", { exact: true })).toBeVisible();
    await expect(filesCard).toBeVisible();
    await expect(filesCard.getByText("evil.jar!/com/acme/Bootstrap.class", { exact: true })).toBeVisible();
    await expect(filesCard.getByText("evil.jar!/com/acme/Secrets.class", { exact: true })).toBeVisible();
    await expect(filesCard.getByText("evil.jar!/../../../etc/passwd", { exact: true })).toBeVisible();
    await expect(filesCard.getByText("evil.jar!/libsigar.so", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("java-outbound-http", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("java-env-read", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("java-static-init", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("zip-path-traversal", { exact: true })).toBeVisible();
    await expect(staticReportCard.getByText("bundled-native-artifact", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Sandbox Telemetry" }).click();
    await expect(page.getByText("No sandbox telemetry is available.")).toBeVisible();

    await page.getByRole("button", { name: "AI Explanation" }).click();
    const aiPanel = page.getByTestId("artifact-ai-explanation-panel");
    await expect(
      aiPanel.getByText("AI explanation is advisory only and never the sole enforcement authority."),
    ).toBeVisible();
    await expect(aiPanel.getByText("Langfuse Trace")).toBeVisible();
    await expect(aiPanel.getByText("langfuse-trace-maven-001", { exact: true })).toBeVisible();
    await expect(aiPanel.locator("pre")).toContainText("advisory_only");

    await page.getByRole("button", { name: "Audit Trail" }).click();
    await expect(page.getByText("analysis.summary.completed")).toBeVisible();
    await expect(page.getByText(`analysis-job/${mockMavenQueueItem.analysis_job_id}`)).toBeVisible();
  });
});