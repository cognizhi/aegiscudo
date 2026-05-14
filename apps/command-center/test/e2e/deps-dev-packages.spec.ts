import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";

const mockPackages = [
  {
    purl: "pkg:npm/lodash@4.17.21",
    ecosystem: "npm",
    namespace: null,
    package_name: "lodash",
    package_version: "4.17.21",
    licenses: ["MIT"],
    dependency_count: 0,
    source_repo_url: "https://github.com/lodash/lodash",
  },
  {
    purl: "pkg:pypi/requests@2.31.0",
    ecosystem: "pypi",
    namespace: null,
    package_name: "requests",
    package_version: "2.31.0",
    licenses: ["Apache-2.0"],
    dependency_count: 5,
    source_repo_url: null,
  },
];

const mockResponse = {
  packages: mockPackages,
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

test.describe("Analysis: deps.dev Package Intelligence", () => {
  test("renders package rows with name, version, ecosystem and license", async ({ page }) => {
    let capturedActorHeader: string | undefined;

    await page.route(`**/api/tenants/${tenantId}/deps-dev/packages**`, async (route) => {
      capturedActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockResponse });
    });

    await openEvidence(page);

    await expect(page.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21")).toBeVisible();
    await expect(
      page.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21").getByText("4.17.21"),
    ).toBeVisible();
    await expect(
      page.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21").getByText("npm", { exact: true }),
    ).toBeVisible();
    await expect(
      page.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21").getByText("MIT"),
    ).toBeVisible();
    expect(capturedActorHeader).toBe(platformAdminActorId);
  });

  test("renders a source repo link for packages that have one", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/deps-dev/packages**`, async (route) => {
      await route.fulfill({ json: mockResponse });
    });

    await openEvidence(page);

    const lodashRow = page.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21");
    const repoLink = lodashRow.getByRole("link", { name: /repo/i });
    await expect(repoLink).toBeVisible();
    await expect(repoLink).toHaveAttribute("href", "https://github.com/lodash/lodash");
    await expect(repoLink).toHaveAttribute("target", "_blank");
    await expect(repoLink).toHaveAttribute("rel", "noopener noreferrer");

    // requests has no source repo — no link in that row
    const requestsRow = page.getByTestId("deps-dev-row-pkg:pypi/requests@2.31.0");
    await expect(requestsRow.getByRole("link")).toHaveCount(0);
  });

  test("shows an empty state when no packages are available", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/deps-dev/packages**`, async (route) => {
      await route.fulfill({ json: { packages: [], total: 0, snapshot_taken_at: null } });
    });

    await openEvidence(page);

    await expect(
      page.getByText(/no deps\.dev package records found/i),
    ).toBeVisible();
  });
});
