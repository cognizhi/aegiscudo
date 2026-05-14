import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";

const mockRecords = [
  {
    id: "aaaaaaaa-0001-0001-0001-000000000001",
    ecosystem: "npm",
    namespace: null,
    package_name: "evil-package",
    package_version: "1.0.0",
    indicator_type: "package-name",
    indicator_value: "evil-package",
  },
  {
    id: "aaaaaaaa-0001-0001-0001-000000000002",
    ecosystem: "pypi",
    namespace: null,
    package_name: "malicious-lib",
    package_version: null,
    indicator_type: "maintainer-identity",
    indicator_value: "bad-actor@example.com",
  },
];

const mockResponse = {
  records: mockRecords,
  total: 2,
  snapshot_taken_at: "2026-05-14T10:00:00Z",
};

async function openEvidence(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible({
    timeout: 30_000,
  });
  await page.getByRole("button", { name: "Evidence" }).click();
  await expect(page.getByRole("heading", { name: "Artifact Evidence" })).toBeVisible();
}

test.describe("Analysis: Cross-Ecosystem IOC Correlation", () => {
  test("renders IOC record rows with package name, ecosystem, indicator type and value", async ({ page }) => {
    let capturedActorHeader: string | undefined;

    await page.route(`**/api/tenants/${tenantId}/ioc-records**`, async (route) => {
      capturedActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockResponse });
    });

    // mock all other evidence routes to avoid noise
    await page.route(`**/api/tenants/${tenantId}/deps-dev/packages**`, async (route) => {
      await route.fulfill({ json: { packages: [], total: 0 } });
    });

    await openEvidence(page);

    await expect(page.getByTestId(`ioc-row-${mockRecords[0].id}`)).toBeVisible();
    await expect(page.getByTestId(`ioc-row-${mockRecords[1].id}`)).toBeVisible();

    // actor header forwarded
    expect(capturedActorHeader).toBe(platformAdminActorId);

    // first row content
    const row1 = page.getByTestId(`ioc-row-${mockRecords[0].id}`);
    await expect(row1.getByText("evil-package").first()).toBeVisible();
    await expect(row1.getByText("npm")).toBeVisible();
    await expect(row1.getByText("package-name", { exact: true })).toBeVisible();

    // second row content
    const row2 = page.getByTestId(`ioc-row-${mockRecords[1].id}`);
    await expect(row2.getByText("bad-actor@example.com")).toBeVisible();
    await expect(row2.getByText("maintainer-identity", { exact: true })).toBeVisible();
    // no version => shows "any"
    await expect(row2.getByText("any")).toBeVisible();
  });

  test("shows snapshot timestamp banner", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/ioc-records**`, async (route) => {
      await route.fulfill({ json: mockResponse });
    });

    await openEvidence(page);

    await expect(page.getByText(/snapshot taken/i)).toBeVisible();
  });

  test("shows empty state when no IOC records are available", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/ioc-records**`, async (route) => {
      await route.fulfill({ json: { records: [], total: 0, snapshot_taken_at: null } });
    });

    await openEvidence(page);

    await expect(
      page.getByText(/no ioc records found/i),
    ).toBeVisible();
  });
});
