import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";
const platformAdminActorId = "018f4a6f-55d0-7000-8000-000000000011";

const mockProfiles = [
  {
    id: "profile-alpha",
    tenant_id: tenantId,
    name: "Alpha Profile",
    mode: "enforce",
    latest_version_id: "ver-alpha-001",
    latest_version: "1",
    latest_effective_at: "2026-05-01T00:00:00Z",
    created_at: "2026-05-01T00:00:00Z",
    request_count_last_30_days: 120,
  },
  {
    id: "profile-beta",
    tenant_id: tenantId,
    name: "Beta Profile",
    mode: "audit",
    latest_version_id: "ver-beta-001",
    latest_version: "1",
    latest_effective_at: "2026-05-10T00:00:00Z",
    created_at: "2026-05-10T00:00:00Z",
    request_count_last_30_days: 45,
  },
];

const mockThresholdsAlpha = {
  policy_profile_id: "profile-alpha",
  policy_version_id: "a1b2c3d4-0000-0000-0000-000000000001",
  code_review: { min_score: 7.0, action: "block", enabled: true },
  branch_protection: { min_score: 6.0, action: "warn", enabled: true },
  ci_cd: { min_score: 5.0, action: "warn", enabled: true },
  maintained: { min_score: 4.0, action: "warn", enabled: false },
  signed_releases: { min_score: 0.0, action: "allow", enabled: false },
};

const mockThresholdsBeta = {
  policy_profile_id: "profile-beta",
  policy_version_id: "b9c8d7e6-0000-0000-0000-000000000002",
  code_review: { min_score: 9.0, action: "block", enabled: true },
  branch_protection: { min_score: 8.0, action: "block", enabled: true },
  ci_cd: { min_score: 8.0, action: "block", enabled: true },
  maintained: { min_score: 7.0, action: "block", enabled: true },
  signed_releases: { min_score: 5.0, action: "block", enabled: true },
};

async function openEvidence(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible({
    timeout: 30_000,
  });
  await page.getByRole("button", { name: "Evidence" }).click();
  await expect(page.getByRole("heading", { name: "Artifact Evidence" })).toBeVisible();
}

test.describe("Analysis: Scorecard Thresholds", () => {
  test("renders scorecard check cards with min-scores and enforcement actions through the persona-backed route", async ({
    page,
  }) => {
    let profilesActorHeader: string | undefined;
    let thresholdsActorHeader: string | undefined;

    await page.route(`**/api/tenants/${tenantId}/policy-profiles`, async (route) => {
      profilesActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
      await route.fulfill({ json: mockProfiles });
    });

    await page.route(
      `**/api/tenants/${tenantId}/policy-profiles/profile-alpha/scorecard-thresholds`,
      async (route) => {
        thresholdsActorHeader = route.request().headers()["x-aegiscudo-actor-id"];
        await route.fulfill({ json: mockThresholdsAlpha });
      },
    );

    await openEvidence(page);

    // Panel heading
    await expect(page.getByRole("region", { name: "Scorecard policy thresholds" })).toBeVisible();
    await expect(page.getByText("OpenSSF Scorecard Thresholds")).toBeVisible();

    // All five check cards rendered
    for (const label of [
      "Code Review",
      "Branch Protection",
      "CI / CD",
      "Maintained",
      "Signed Releases",
    ]) {
      await expect(page.getByText(label)).toBeVisible();
    }

    // Code Review card: 7.0, Block
    const codeReviewCard = page.getByTestId("scorecard-check-code_review");
    await expect(codeReviewCard.getByText("7.0")).toBeVisible();
    await expect(codeReviewCard.getByText("Block")).toBeVisible();

    // Branch Protection: 6.0, Warn
    const branchCard = page.getByTestId("scorecard-check-branch_protection");
    await expect(branchCard.getByText("6.0")).toBeVisible();
    await expect(branchCard.getByText("Warn")).toBeVisible();

    // Maintained: disabled
    await expect(page.getByTestId("scorecard-check-maintained").getByText("disabled")).toBeVisible();

    // Signed Releases: disabled
    await expect(
      page.getByTestId("scorecard-check-signed_releases").getByText("disabled"),
    ).toBeVisible();

    // Policy version footer
    await expect(page.getByText(/a1b2c3d4/)).toBeVisible();

    // Actor headers forwarded via the proxy
    await expect.poll(() => profilesActorHeader).toBe(platformAdminActorId);
    await expect.poll(() => thresholdsActorHeader).toBe(platformAdminActorId);
  });

  test("shows profile selector when multiple profiles are available and switches on selection", async ({
    page,
  }) => {
    await page.route(`**/api/tenants/${tenantId}/policy-profiles`, async (route) => {
      await route.fulfill({ json: mockProfiles });
    });

    await page.route(
      `**/api/tenants/${tenantId}/policy-profiles/profile-alpha/scorecard-thresholds`,
      async (route) => {
        await route.fulfill({ json: mockThresholdsAlpha });
      },
    );

    await page.route(
      `**/api/tenants/${tenantId}/policy-profiles/profile-beta/scorecard-thresholds`,
      async (route) => {
        await route.fulfill({ json: mockThresholdsBeta });
      },
    );

    await openEvidence(page);

    // Profile selector visible
    const profileSelect = page.getByRole("combobox", { name: /policy profile for scorecard/i });
    await expect(profileSelect).toBeVisible();
    await expect(profileSelect).toHaveValue("profile-alpha");

    // Alpha thresholds shown initially
    await expect(page.getByTestId("scorecard-check-code_review").getByText("7.0")).toBeVisible();

    // Switch to Beta Profile
    await profileSelect.selectOption("profile-beta");

    // Beta thresholds shown after switch
    await expect(page.getByTestId("scorecard-check-code_review").getByText("9.0")).toBeVisible();
    await expect(page.getByTestId("scorecard-check-maintained").getByText("Block")).toBeVisible();
    await expect(page.getByText(/b9c8d7e6/)).toBeVisible();
  });

  test("each check card has a tooltip help button", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/policy-profiles`, async (route) => {
      await route.fulfill({ json: [mockProfiles[0]] });
    });

    await page.route(
      `**/api/tenants/${tenantId}/policy-profiles/profile-alpha/scorecard-thresholds`,
      async (route) => {
        await route.fulfill({ json: mockThresholdsAlpha });
      },
    );

    await openEvidence(page);

    // All 5 check cards have their help buttons
    for (const label of [
      "Code Review check description",
      "Branch Protection check description",
      "CI / CD check description",
      "Maintained check description",
      "Signed Releases check description",
    ]) {
      await expect(page.getByRole("button", { name: label })).toBeVisible();
    }
  });
});
