import { expect, test } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const cisoAuditorActorId = "018f4a6f-55d0-7000-8000-000000000023";

test("dashboard shell renders seeded investigation workflow", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible();
  await expect(page.getByText("Package Request Timeline")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Override Queue" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Pending \(\d+\)/ })).toBeVisible();
  await expect(page.getByText("Temporary analyst review bypass")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByLabel("Override queue")).toContainText("Under 24h", { timeout: 30_000 });
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("override reason must contain at least 8 non-whitespace characters")).toBeVisible();
  await page.getByLabel(/Review note for/i).fill("Incident approved with analyst justification.");
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByLabel("Override queue")).not.toContainText("Temporary analyst review bypass");
  const resolvedTab = page.getByRole("button", { name: /Resolved \(\d+\)/ });
  await expect(resolvedTab).toBeVisible();
  await resolvedTab.click();
  await expect(
    page.getByRole("row", { name: /Temporary analyst review bypass/ }),
  ).toContainText("Local Admin");
  await expect(page.getByText("Quarantine 1")).toBeVisible();
  await expect(page.getByText("Block 1")).toBeVisible();
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).toContainText("trace-block-003");
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).toContainText("QUARANTINE_PENDING_ANALYSIS");
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).toContainText("BLOCK_POLICY_VIOLATION");
  await page.getByLabel("Search quarantine queue").fill("requestz");
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).toContainText("pkg:pypi/requestz@99.0.0");
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).not.toContainText("fresh-postinstall");
  await page.getByLabel("Search quarantine queue").fill("");
  await page.getByRole("button", { name: "Package" }).click();
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).toContainText("pkg:npm/fresh-postinstall@0.1.0");
  await page.getByLabel("Rows per page").selectOption("1");
  await expect(page.getByText("Page 1 of 2")).toBeVisible();
  await page.getByRole("button", { name: "Next queue page" }).click();
  await expect(page.getByText("Page 2 of 2")).toBeVisible();
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).toContainText("trace-block-003");
  await page.getByRole("button", { name: "Previous queue page" }).click();
  await expect(page.getByText("Page 1 of 2")).toBeVisible();
  await page.getByLabel("Search quarantine queue").fill("requestz");
  await page
    .getByLabel("Quarantine queue")
    .getByRole("row", { name: /pkg:pypi\/requestz@99\.0\.0/ })
    .click();
  await expect(page.getByText("Artifact Evidence Viewer")).toBeVisible();
  await expect(page.getByRole("heading", { name: "pkg:pypi/requestz@99.0.0" })).toBeVisible();
  await expect(page.getByText("Canary credential access was attempted.")).toBeVisible();

  await expect(page.getByText("Emergency unblock for incident triage")).toBeVisible();
  await expect(page.getByText("Request lacked incident justification")).toBeVisible();

  await page.getByRole("button", { name: "Static Analysis" }).click();
  await expect(page.getByText("Files")).toBeVisible();
  await expect(page.getByText("Analyzer fixture-static-1.0.0")).toBeVisible();
  await expect(page.getByText("typosquat-distance")).toBeVisible();

  await page.getByRole("button", { name: "Sandbox Telemetry" }).click();
  await expect(page.getByText("canary-secret-access")).toBeVisible();

  await page.getByRole("button", { name: "AI Explanation" }).click();
  await expect(page.getByText("AI explanation is advisory only and never the sole enforcement authority.")).toBeVisible();
  await expect(page.getByText("Langfuse Trace")).toBeVisible();
  await expect(page.getByText("langfuse-trace-block-003", { exact: true })).toBeVisible();
  await expect(page.getByText('"advisory_only": true')).toBeVisible();

  await page.getByRole("button", { name: "Audit Trail" }).click();
  await expect(page.getByText("analysis.summary.completed")).toBeVisible();

  await page.getByLabel("Search quarantine queue").fill("");
  await expect(page.getByLabel("Quarantine queue").getByRole("table")).toContainText("pkg:npm/fresh-postinstall@0.1.0");
  await expect(page.getByRole("heading", { name: "pkg:npm/fresh-postinstall@0.1.0" })).toBeVisible();
  await expect(page.getByText("Sandbox evidence is missing for this artifact.")).toBeVisible();

  await page.getByRole("button", { name: "Static Analysis" }).click();
  await expect(page.getByText("Files")).toBeVisible();
  await expect(page.getByText("Rules fixture-rules-2026.05.05")).toBeVisible();
  await expect(page.getByText("lifecycle-script")).toBeVisible();

  await page.getByRole("button", { name: "Sandbox Telemetry" }).click();
  await expect(page.getByText("No sandbox telemetry is available.")).toBeVisible();
});

test("persona switching revokes protected admin navigation", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("button", { name: "LLM Usage" })).toBeVisible();
  await page.getByRole("button", { name: "Audit Log" }).click();
  await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();

  await page.getByLabel("Persona").selectOption("developer");

  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Audit Log" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Integrations" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "LLM Usage" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Evidence" })).toBeVisible();

  await page.getByLabel("Persona").selectOption("ciso-auditor");

  await expect(page.getByRole("button", { name: "Audit Log" })).toBeVisible();
  await expect(page.getByRole("button", { name: "LLM Usage" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Evidence" })).toHaveCount(0);
});

test("ciso auditor receives a live forbidden audit log response", async ({ request }) => {
  const response = await request.get(`/api/tenants/${tenantId}/audit-events`, {
    headers: { "x-aegiscudo-actor-id": cisoAuditorActorId },
  });

  expect(response.status()).toBe(403);
  await expect(response.json()).resolves.toEqual({
    message: "request actor is not authorized",
  });
});

test("platform admin can review live seeded LLM usage metrics", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "LLM Usage" }).click();

  await expect(page.getByRole("heading", { name: "LLM Usage" })).toBeVisible();
  await expect(page.getByText("local-openrouter", { exact: true })).toBeVisible();
  await expect(page.getByText("qwen/qwen3.6-plus").first()).toBeVisible();
  await expect(page.getByText("analysis-preview-v1").first()).toBeVisible();
  await expect(page.getByText("trace-block-003")).toBeVisible();
});

test("platform admin can review live seeded AI provider and audit views", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "AI Providers" }).click();
  await expect(page.getByRole("heading", { name: "AI Providers" })).toBeVisible();
  const providerRow = page.getByRole("row", { name: /local-openrouter/ });
  await expect(providerRow).toBeVisible();
  await expect(providerRow.getByText("OpenRouter", { exact: true })).toBeVisible();
  await expect(providerRow.getByText("qwen/qwen3.6-plus")).toBeVisible();
  await expect(providerRow.getByText("Cloud", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Audit Log" }).click();
  await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();
  const summaryRow = page.getByRole("row", {
    name: /analysis\.summary\.completed.*analysis-job\/018f4a6f-55d0-7000-8000-000000000802/,
  });
  const requestRow = page.getByRole("row", {
    name: /package-request\.recorded.*package-request\/018f4a6f-55d0-7000-8000-000000000502/,
  });
  await expect(summaryRow).toBeVisible();
  await expect(requestRow).toBeVisible();
  await expect(summaryRow.getByText("system/fixture-seed")).toBeVisible();
});

test("breadcrumb has WCAG-compliant semantic structure and updates on navigation", async ({ page }) => {
  await page.goto("/");

  const breadcrumb = page.getByTestId("breadcrumb");
  await expect(breadcrumb).toBeVisible();

  // Verify the breadcrumb nav landmark has the correct label
  const nav = page.getByRole("navigation", { name: "Breadcrumb" });
  await expect(nav).toBeVisible();

  // Default view: "Overview / Risk" — last segment has aria-current="page"
  const currentItem = breadcrumb.locator('[aria-current="page"]');
  await expect(currentItem).toHaveText("Risk");

  // Navigate to Analysis / Evidence — breadcrumb should update
  await page.getByRole("button", { name: "Evidence" }).click();
  await expect(currentItem).toHaveText("Evidence");
  await expect(breadcrumb).toContainText("Analysis");

  // Navigate to Admin / Audit Log — breadcrumb should show two segments
  await page.getByRole("button", { name: "Audit Log" }).click();
  await expect(currentItem).toHaveText("Audit Log");
  await expect(breadcrumb).toContainText("Admin");
});
