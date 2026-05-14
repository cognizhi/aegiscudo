import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";

const mockSbomDocuments = [
  {
    id: "sbom-1",
    analysis_job_id: null,
    tenant_id: tenantId,
    format: "cyclonedx-1.7-json",
    source: "Cargo.lock",
    component_count: 42,
    storage_size_bytes: 4096,
    created_at: "2026-05-14T09:30:00Z",
    ntia_validation: {
      valid: false,
      issues: ["missing metadata.component.name"],
    },
  },
];

async function openShell(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible({
    timeout: 30_000,
  });
}

test.describe("Analysis: SBOM Exports", () => {
  test("renders recent tenant SBOM exports and downloads through the persona-backed route", async ({ page }) => {
    let listActorHeader: string | undefined;
    let downloadActorHeader: string | undefined;

    await page.route(`**/api/tenants/${tenantId}/analysis/sboms?limit=12`, async (route) => {
      listActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockSbomDocuments });
    });

    await page.route(`**/api/tenants/${tenantId}/analysis/sboms/sbom-1`, async (route) => {
      downloadActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-disposition": 'attachment; filename="cargo-lock.json"',
        },
        body: '{"bomFormat":"CycloneDX"}',
      });
    });

    await openShell(page);
    await page.getByRole("button", { name: "Evidence" }).click();

    const expectedCreatedAt = await page.evaluate(
      (value) => new Date(value).toLocaleString(),
      mockSbomDocuments[0]?.created_at ?? "",
    );

    await expect(page.getByRole("heading", { name: "Artifact Evidence" })).toBeVisible();
    await expect(page.getByText("SBOM Exports")).toBeVisible();
    await expect(
      page.getByText(
        "Recent tenant-scoped SBOM documents stored by sbom-service and ready for export.",
      ),
    ).toBeVisible();
    await expect(page.getByText("Cargo.lock")).toBeVisible();
    await expect(page.getByText("CycloneDX 1.7")).toBeVisible();
    await expect(page.getByText("42")).toBeVisible();
    await expect(page.getByText("4.0 KB")).toBeVisible();
    await expect(page.getByText(expectedCreatedAt)).toBeVisible();
    await expect(page.getByText("1 NTIA issue")).toBeVisible();
    await expect(page.getByText("missing metadata.component.name")).toBeVisible();
    await expect
      .poll(() => listActorHeader)
      .toBe(platformAdminActorId);

    const downloadButton = page.getByRole("button", {
      name: "Download SBOM for Cargo.lock",
    });
    await Promise.all([
      page.waitForResponse(`**/api/tenants/${tenantId}/analysis/sboms/sbom-1`),
      downloadButton.click(),
    ]);

    await expect.poll(() => downloadActorHeader).toBe(platformAdminActorId);
    await expect(downloadButton).toHaveText("Download JSON");
  });
});