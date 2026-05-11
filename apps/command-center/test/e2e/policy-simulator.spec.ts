import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";

const defaultProfile = {
  id: "018f4a6f-55d0-7000-8000-000000000101",
  tenant_id: tenantId,
  name: "Default Enforce",
  mode: "enforce",
  latest_version_id: "018f4a6f-55d0-7000-8000-000000000201",
  latest_version: "v1",
  latest_effective_at: "2026-05-05T10:00:00Z",
  created_at: "2026-05-05T09:55:00Z",
  request_count_last_30_days: 42,
} as const;

const shadowProfile = {
  id: "018f4a6f-55d0-7000-8000-000000000102",
  tenant_id: tenantId,
  name: "Shadow Replay",
  mode: "shadow",
  latest_version_id: "018f4a6f-55d0-7000-8000-000000000202",
  latest_version: "v2",
  latest_effective_at: "2026-05-06T10:00:00Z",
  created_at: "2026-05-06T09:55:00Z",
  request_count_last_30_days: 42,
} as const;

const mockPolicyProfiles = [defaultProfile, shadowProfile];

const mockPolicySimulation = {
  tenant_id: tenantId,
  target_policy_profile_id: shadowProfile.id,
  target_policy_profile_name: shadowProfile.name,
  target_policy_mode: shadowProfile.mode,
  target_latest_version_id: shadowProfile.latest_version_id,
  target_latest_version: shadowProfile.latest_version,
  lookback_days: 30,
  ecosystem: "npm",
  replayed_request_count: 2,
  changed_request_count: 1,
  baseline_counts: {
    allow: 1,
    allow_with_warning: 0,
    quarantine_pending_analysis: 0,
    block_known_malicious: 0,
    block_policy_violation: 1,
    require_hitl_approval: 0,
    fallback_to_approved_candidate: 0,
  },
  simulated_counts: {
    allow: 0,
    allow_with_warning: 1,
    quarantine_pending_analysis: 0,
    block_known_malicious: 0,
    block_policy_violation: 1,
    require_hitl_approval: 0,
    fallback_to_approved_candidate: 0,
  },
  items: [
    {
      package_request_id: "018f4a6f-55d0-7000-8000-000000000301",
      trace_id: "trace-policy-one",
      requested_at: "2026-05-08T09:00:00Z",
      coordinate: {
        ecosystem: "npm",
        name: "left-pad",
        version: "1.3.0",
      },
      baseline_policy_profile_id: defaultProfile.id,
      baseline_policy_profile_name: defaultProfile.name,
      baseline_decision: "ALLOW",
      baseline_rationale: ["no blocking policy signal matched"],
      simulated_decision: "ALLOW_WITH_WARNING",
      simulated_rationale: ["install or lifecycle script requires review"],
      changed: true,
    },
    {
      package_request_id: "018f4a6f-55d0-7000-8000-000000000302",
      trace_id: "trace-policy-two",
      requested_at: "2026-05-08T09:05:00Z",
      coordinate: {
        ecosystem: "npm",
        name: "fresh-postinstall",
        version: "0.1.0",
      },
      baseline_policy_profile_id: defaultProfile.id,
      baseline_policy_profile_name: defaultProfile.name,
      baseline_decision: "BLOCK_POLICY_VIOLATION",
      baseline_rationale: ["static analysis score exceeded the configured policy threshold"],
      simulated_decision: "BLOCK_POLICY_VIOLATION",
      simulated_rationale: ["static analysis score exceeded the configured policy threshold"],
      changed: false,
    },
  ],
  generated_at: "2026-05-10T10:00:00Z",
};

async function openShell(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible({ timeout: 30_000 });
}

test.describe("Policy Simulator", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/policy-profiles`, async (route) => {
      await route.fulfill({ json: mockPolicyProfiles });
    });
  });

  test("replays the selected policy profile and renders a decision diff", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/policy-simulator/replay`, async (route) => {
      const body = route.request().postDataJSON() as {
        policy_profile_id?: string;
        ecosystem?: string;
        lookback_days?: number;
      };

      expect(body.policy_profile_id).toBe(shadowProfile.id);
      expect(body.ecosystem).toBe("npm");
      expect(body.lookback_days).toBe(30);

      await route.fulfill({ json: mockPolicySimulation });
    });

    await openShell(page);
    await page.getByRole("button", { name: "Simulator" }).click();

    await expect(page.getByRole("heading", { name: "Policy Simulator", level: 1 })).toBeVisible();
    await page.getByLabel("Target policy profile").selectOption(shadowProfile.id);
    await page.getByLabel("Ecosystem").selectOption("npm");
    await page.getByRole("button", { name: "Run Replay" }).click();

    await expect(page.getByText("Requests evaluated")).toBeVisible();
    await expect(page.getByText("left-pad@1.3.0")).toBeVisible();
    await expect(page.getByText("ALLOW_WITH_WARNING")).toBeVisible();
    await expect(page.getByText(/Targeting\s+Shadow Replay\s+in\s+shadow\s+mode\s+using snapshot\s+v2\./)).toBeVisible();
    await expect(page.getByText("npm · changed")).toBeVisible();
  });

  test("shows an empty state when no policy profiles exist", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/policy-profiles`, async (route) => {
      await route.fulfill({ json: [] });
    });

    await openShell(page);
    await page.getByRole("button", { name: "Simulator" }).click();
    await expect(page.getByText("No policy profiles are available for replay in this tenant.")).toBeVisible();
  });
});