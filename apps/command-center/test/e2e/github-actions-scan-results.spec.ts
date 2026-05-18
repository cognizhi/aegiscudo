import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";

const allowResult = {
  id: "bbbbbbbb-0001-0001-0001-000000000001",
  tenant_id: tenantId,
  policy_profile_id: "cccccccc-0001-0001-0001-000000000001",
  owner: "acme-corp",
  repo: "deploy-pipeline",
  ref: "v1.2.3",
  decision: "ALLOW",
  rationale: ["no blocking policy signal matched"],
  trace_id: "trace-allow-001",
  fallback_ref: null,
  scanned_at: "2024-03-15T10:00:00Z",
};

const blockResult = {
  id: "bbbbbbbb-0001-0001-0001-000000000002",
  tenant_id: tenantId,
  policy_profile_id: "cccccccc-0001-0001-0001-000000000001",
  owner: "evil-org",
  repo: "compromised-actions",
  ref: "v0.0.1",
  decision: "BLOCK_POLICY_VIOLATION",
  rationale: ["action pinned to mutable tag", "unknown publisher"],
  trace_id: "trace-block-002",
  fallback_ref: null,
  scanned_at: "2024-03-15T11:00:00Z",
};

const mockResults = [allowResult, blockResult];

async function openEvidence(page: Page) {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Executive Risk Dashboard" }),
  ).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Evidence" }).click();
  await expect(
    page.getByRole("heading", { name: "Artifact Evidence" }),
  ).toBeVisible();
}

async function mockSilentRoutes(page: Page) {
  await page.route(
    `**/api/tenants/${tenantId}/deps-dev/packages**`,
    async (route) => route.fulfill({ json: { packages: [], total: 0 } }),
  );
  await page.route(
    `**/api/tenants/${tenantId}/ioc-records**`,
    async (route) =>
      route.fulfill({ json: { records: [], total: 0, snapshot_taken_at: null } }),
  );
}

test.describe("Analysis: GitHub Actions Workflow Integrity", () => {
  test("renders scan result rows with owner/repo, ref, decision, and rationale", async ({
    page,
  }) => {
    let capturedActorHeader: string | undefined;

    await mockSilentRoutes(page);
    await page.route(
      `**/api/tenants/${tenantId}/github-actions/scan-results**`,
      async (route) => {
        capturedActorHeader =
          route.request().headers()["x-aegiscudo-actor-id"];
        await route.fulfill({ json: mockResults });
      },
    );

    await openEvidence(page);

    await expect(
      page.getByTestId(`gha-row-${allowResult.id}`),
    ).toBeVisible();
    await expect(
      page.getByTestId(`gha-row-${blockResult.id}`),
    ).toBeVisible();

    // actor header forwarded
    expect(capturedActorHeader).toBe(platformAdminActorId);

    // first row: owner/repo and ref
    const row1 = page.getByTestId(`gha-row-${allowResult.id}`);
    await expect(row1.getByText("acme-corp/deploy-pipeline")).toBeVisible();
    await expect(row1.getByText("v1.2.3")).toBeVisible();

    // second row: blocking decision and rationale
    const row2 = page.getByTestId(`gha-row-${blockResult.id}`);
    await expect(row2.getByText("evil-org/compromised-actions")).toBeVisible();
    await expect(row2.getByText("action pinned to mutable tag")).toBeVisible();
  });

  test("shows BLOCK decision badge with correct visual class", async ({
    page,
  }) => {
    await mockSilentRoutes(page);
    await page.route(
      `**/api/tenants/${tenantId}/github-actions/scan-results**`,
      async (route) => route.fulfill({ json: [blockResult] }),
    );

    await openEvidence(page);

    const badge = page.locator(
      `[data-testid="gha-row-${blockResult.id}"] [data-decision="BLOCK_POLICY_VIOLATION"]`,
    );
    await expect(badge).toBeVisible();
    await expect(badge).toHaveClass(/status-block/);
  });

  test("shows empty state when no scan results are available", async ({
    page,
  }) => {
    await mockSilentRoutes(page);
    await page.route(
      `**/api/tenants/${tenantId}/github-actions/scan-results**`,
      async (route) => route.fulfill({ json: [] }),
    );

    await openEvidence(page);

    await expect(
      page.getByText(/no github actions scan results yet/i),
    ).toBeVisible();
  });
});
