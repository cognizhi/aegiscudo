import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";

const mockOpenVexDocuments = [
  {
    id: "openvex-1",
    tenant_id: tenantId,
    source: "fixture-openvex.json",
    document_id: "https://fixtures.aegiscudo.invalid/openvex/acme-2026-001",
    author: "Aegiscudo Fixture Suite",
    context: "https://openvex.dev/ns/v0.2.0",
    version: 1,
    document_timestamp: "2026-05-12T08:00:00Z",
    imported_at: "2026-05-13T10:00:00Z",
    expiry_policy: { mode: "never" },
    document_digest: "a".repeat(64),
    statement_count: 2,
  },
  {
    id: "openvex-2",
    tenant_id: tenantId,
    source: "partner-openvex.json",
    document_id: "https://fixtures.aegiscudo.invalid/openvex/partner-2026-004",
    author: "Partner Feed",
    context: "https://openvex.dev/ns/v0.2.0",
    version: 4,
    document_timestamp: "2026-05-13T09:15:00Z",
    imported_at: "2026-05-13T10:30:00Z",
    expiry_policy: { mode: "expires-at", expires_at: "2099-05-13T10:30:00Z" },
    document_digest: "b".repeat(64),
    statement_count: 1,
  },
];

const mockOpenVexDetailOne = {
  ...mockOpenVexDocuments[0],
  document: {
    statements: [
      {
        vulnerability: { name: "CVE-2026-0001" },
        products: [{ "@id": "pkg:npm/left-pad@1.3.0" }],
        status: "not_affected",
        justification: "component_not_present",
      },
      {
        vulnerability: { name: "CVE-2026-0002" },
        products: [{ "@id": "pkg:pypi/requests@2.31.0" }],
        status: "fixed",
        action_statement: "Patched in upstream release 2.31.0",
      },
    ],
  },
};

const mockOpenVexDetailTwo = {
  ...mockOpenVexDocuments[1],
  document: {
    statements: [
      {
        vulnerability: { name: "CVE-2026-2222" },
        products: [{ "@id": "pkg:cargo/cargo-evil@0.1.0" }],
        status: "under_investigation",
        impact_statement: "Cargo artifact still being reviewed by the response team.",
      },
    ],
  },
};

async function openShell(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible({
    timeout: 30_000,
  });
}

test.describe("Analysis: OpenVEX Import State", () => {
  test("renders imported OpenVEX documents through persona-backed routes", async ({ page }) => {
    let listActorHeader: string | undefined;
    let detailOneActorHeader: string | undefined;
    let detailTwoActorHeader: string | undefined;

    await page.route(`**/api/tenants/${tenantId}/analysis/sboms?limit=12`, async (route) => {
      await route.fulfill({ json: [] });
    });

    await page.route(`**/api/tenants/${tenantId}/analysis/openvex-documents`, async (route) => {
      listActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockOpenVexDocuments });
    });

    await page.route(`**/api/tenants/${tenantId}/analysis/openvex-documents/openvex-1`, async (route) => {
      detailOneActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockOpenVexDetailOne });
    });

    await page.route(`**/api/tenants/${tenantId}/analysis/openvex-documents/openvex-2`, async (route) => {
      detailTwoActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockOpenVexDetailTwo });
    });

    await openShell(page);
    await page.getByRole("button", { name: "Evidence" }).click();

    await expect(page.getByRole("heading", { name: "Artifact Evidence" })).toBeVisible();
    const openVexPanel = page.getByTestId("openvex-documents-panel");
    await expect(openVexPanel.getByText("OpenVEX Import State")).toBeVisible();
    await expect(
      openVexPanel.getByText(
        "Imported tenant-scoped OpenVEX documents and their statement history for the active tenant.",
      ),
    ).toBeVisible();
    await expect(openVexPanel.getByRole("button", { name: /fixture-openvex\.json/i })).toBeVisible();
    await expect(openVexPanel.getByRole("button", { name: /partner-openvex\.json/i })).toBeVisible();
    await expect(openVexPanel.getByRole("heading", { name: "fixture-openvex.json" })).toBeVisible();
    await expect.poll(() => listActorHeader).toBe(platformAdminActorId);
    await expect.poll(() => detailOneActorHeader).toBe(platformAdminActorId);

    await expect(page.getByTestId("openvex-summary-statements-value")).toHaveText("2");
    await expect(page.getByTestId("openvex-summary-suppressed-value")).toHaveText("2");
    await expect(page.getByTestId("openvex-summary-under-investigation-value")).toHaveText("0");
    await expect(page.getByTestId("openvex-summary-affected-value")).toHaveText("0");
    await expect(page.getByTestId("openvex-suppression-state")).toContainText(
      "pending component-level vulnerability correlation",
    );
    const firstStatement = page.getByTestId("openvex-statement-1");
    const secondStatement = page.getByTestId("openvex-statement-2");
    await expect(firstStatement.getByText("CVE-2026-0001")).toBeVisible();
    await expect(firstStatement.getByText("pkg:npm/left-pad@1.3.0")).toBeVisible();
    await expect(firstStatement.getByText("component_not_present")).toBeVisible();
    await expect(secondStatement.getByText("CVE-2026-0002")).toBeVisible();
    await expect(secondStatement.getByText("Patched in upstream release 2.31.0")).toBeVisible();

    await openVexPanel.getByRole("button", { name: /partner-openvex\.json/i }).click();

    await expect.poll(() => detailTwoActorHeader).toBe(platformAdminActorId);
    await expect(page.getByTestId("openvex-summary-statements-value")).toHaveText("1");
    await expect(page.getByTestId("openvex-summary-suppressed-value")).toHaveText("0");
    await expect(page.getByTestId("openvex-summary-under-investigation-value")).toHaveText("1");
    await expect(openVexPanel.getByRole("heading", { name: "partner-openvex.json" })).toBeVisible();
    await expect(firstStatement.getByText("CVE-2026-2222")).toBeVisible();
    await expect(firstStatement.getByText("pkg:cargo/cargo-evil@0.1.0")).toBeVisible();
    await expect(firstStatement.getByText("Cargo artifact still being reviewed by the response team.")).toBeVisible();
  });
});