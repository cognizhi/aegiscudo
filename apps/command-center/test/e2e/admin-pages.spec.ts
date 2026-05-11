import { expect, test, type Page } from "@playwright/test";

const tenantId = "018f4a6f-55d0-7000-8000-000000000001";

const mockRegistryConfigs = [
  {
    id: "rc-0001",
    tenant_id: tenantId,
    name: "NPM Public Mirror",
    adapter: "npm",
    upstream_url: "https://registry.npmjs.org",
    mount_path: "/npm/",
    mode: "enforce",
    enabled: true,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-06-01T00:00:00Z",
  },
  {
    id: "rc-0002",
    tenant_id: tenantId,
    name: "PyPI Mirror",
    adapter: "pypi",
    upstream_url: "https://pypi.org",
    mount_path: "/pypi/",
    mode: "shadow",
    enabled: false,
    created_at: "2025-02-01T00:00:00Z",
    updated_at: "2025-06-02T00:00:00Z",
  },
];

const mockCredentials = [
  {
    id: "cred-0001",
    tenant_id: tenantId,
    name: "NPM Token",
    credential_type: "api_key",
    source: "env",
    configured: true,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-06-01T00:00:00Z",
  },
  {
    id: "cred-0002",
    tenant_id: tenantId,
    name: "AI API Key",
    credential_type: "bearer_token",
    source: "vault",
    configured: false,
    created_at: "2025-02-01T00:00:00Z",
    updated_at: "2025-06-02T00:00:00Z",
  },
];

const mockAiProviders = [
  {
    id: "ai-0001",
    tenant_id: tenantId,
    display_name: "Local Ollama",
    provider_type: "ollama",
    base_url: "http://localhost:11434",
    model_id: "phi3:mini",
    is_local: true,
    active: true,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-06-01T00:00:00Z",
  },
];

const mockLlmUsage = {
  tenant_id: tenantId,
  summary: {
    total_calls: 42,
    prompt_tokens: 10240,
    completion_tokens: 2560,
    total_tokens: 12800,
    estimated_cost: 1.2345,
    avg_latency_ms: 840,
    p95_latency_ms: 1250,
    schema_validation_passes: 40,
    schema_validation_failures: 2,
    redaction_failures: 1,
  },
  calls_by_day: [
    { day: "2025-05-31", total_calls: 11, total_tokens: 3400 },
    { day: "2025-06-01", total_calls: 14, total_tokens: 4200 },
    { day: "2025-06-02", total_calls: 17, total_tokens: 5200 },
  ],
  provider_models: [
    {
      provider_display_name: "OpenRouter Primary",
      provider_type: "openrouter",
      model_id: "openai/o4-mini",
      total_calls: 42,
      prompt_tokens: 10240,
      completion_tokens: 2560,
      total_tokens: 12800,
      estimated_cost: 1.2345,
      avg_latency_ms: 840,
      p95_latency_ms: 1250,
    },
  ],
  analysis_jobs: [
    {
      analysis_job_id: "018f4a6f-55d0-7000-8000-000000000901",
      trace_id: "trace-llm-001",
      provider_display_name: "OpenRouter Primary",
      model_id: "openai/o4-mini",
      total_calls: 2,
      total_tokens: 512,
      estimated_cost: 0.08,
      langfuse_trace_id: "langfuse-trace-ok",
      last_called_at: "2025-06-03T10:00:00Z",
    },
  ],
  failing_traces: [
    {
      analysis_job_id: "018f4a6f-55d0-7000-8000-000000000902",
      trace_id: "trace-llm-002",
      provider_display_name: "OpenRouter Primary",
      provider_type: "openrouter",
      model_id: "openai/o4-mini",
      langfuse_trace_id: "langfuse-trace-failed",
      prompt_template_version: "analysis-preview-v1",
      schema_valid: false,
      redaction_complete: false,
      latency_ms: 1320,
      created_at: "2025-06-03T09:00:00Z",
    },
  ],
  prompt_template_versions: [
    { prompt_template_version: "analysis-preview-v1", total_calls: 42 },
  ],
};

const mockAuditEvents = [
  {
    id: "ae-0001",
    tenant_id: tenantId,
    actor: "user/018f4a6f-55d0-7000-8000-000000000011",
    actor_display: "Local Admin",
    actor_roles: ["platform-admin"],
    action: "allow",
    resource: "pkg:npm/lodash@4.17.21",
    trace_id: "abc12345-6789-abcd-ef01-234567890000",
    occurred_at: "2025-06-01T12:00:00Z",
    metadata: { decision: "ALLOW" },
  },
  {
    id: "ae-0002",
    tenant_id: tenantId,
    actor: "system",
    actor_display: "system",
    actor_roles: [],
    action: "block",
    resource: "pkg:npm/evil-package@1.0.0",
    trace_id: null,
    occurred_at: "2025-06-02T08:30:00Z",
    metadata: {},
  },
];

async function openShell(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeVisible({ timeout: 30_000 });
}

test.describe("Admin: Registry Proxies", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/registry-configs`, (route) => {
      if (route.request().method() === "GET") {
        void route.fulfill({ json: mockRegistryConfigs });
      }
    });
  });

  test("navigates to Registry Proxies and renders table", async ({ page }) => {
    await openShell(page);
    await page.getByRole("button", { name: "Registry" }).click();
    await expect(page.getByRole("heading", { name: "Registry Proxies", level: 1 })).toBeVisible();
    await expect(page.getByRole("button", { name: "Add registry proxy" })).toBeVisible();
    await expect(page.getByText("NPM Public Mirror")).toBeVisible();
    await expect(page.getByText("PyPI Mirror")).toBeVisible();
    await expect(page.getByText("enforce")).toBeVisible();
    await expect(page.getByText("shadow")).toBeVisible();
    await expect(page.getByText("https://registry.npmjs.org")).toBeVisible();
  });

  test("shows coming-soon badge for non-GA adapters", async ({ page }) => {
    await page.unroute(`**/api/tenants/${tenantId}/registry-configs`);
    // Inject a cargo adapter row
    await page.route(`**/api/tenants/${tenantId}/registry-configs`, (route) => {
      void route.fulfill({
        json: [
          ...mockRegistryConfigs,
          {
            id: "rc-0003",
            tenant_id: tenantId,
            name: "Cargo Mirror",
            adapter: "cargo",
            upstream_url: "https://crates.io",
            mount_path: "/cargo/",
            mode: "shadow",
            enabled: false,
            created_at: "2025-03-01T00:00:00Z",
            updated_at: "2025-06-03T00:00:00Z",
          },
        ],
      });
    });

    await openShell(page);
    await page.getByRole("button", { name: "Registry" }).click();
    const cargoRow = page.getByRole("row", { name: /Cargo Mirror/ });
    await expect(cargoRow).toBeVisible();
    await expect(cargoRow.getByText("coming soon", { exact: true })).toBeVisible();
  });
});

test.describe("Admin: AI Providers", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/ai-providers`, (route) => {
      void route.fulfill({ json: mockAiProviders });
    });
  });

  test("navigates to AI Providers and renders table", async ({ page }) => {
    await openShell(page);
    await page.getByRole("button", { name: "AI Providers" }).click();
    await expect(page.getByRole("heading", { name: "AI Providers", level: 1 })).toBeVisible();
    await expect(page.getByText("Local Ollama")).toBeVisible();
    await expect(page.getByText("phi3:mini")).toBeVisible();
    const providerRow = page.getByRole("row", { name: /Local Ollama/ });
    await expect(providerRow.getByText("Local", { exact: true })).toBeVisible();
    await expect(providerRow.getByText("Active", { exact: true })).toBeVisible();
    await expect(page.getByText("http://localhost:11434")).toBeVisible();
    // API key must never be shown
    await expect(page.getByText(/api.?key/i)).not.toBeVisible();
    await expect(page.getByText(/sk-/)).not.toBeVisible();
  });

  test("shows empty state when no providers configured", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/ai-providers`, (route) => {
      void route.fulfill({ json: [] });
    });
    await openShell(page);
    await page.getByRole("button", { name: "AI Providers" }).click();
    await expect(page.getByText("No AI provider configured")).toBeVisible();
  });
});

test.describe("Admin: LLM Usage", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/llm-usage`, (route) => {
      void route.fulfill({ json: mockLlmUsage });
    });
  });

  test("navigates to LLM Usage and renders persisted metrics", async ({ page }) => {
    await openShell(page);
    await page.getByRole("button", { name: "LLM Usage" }).click();
    await expect(page.getByRole("heading", { name: "LLM Usage", level: 1 })).toBeVisible();
    await expect(page.getByText("42").first()).toBeVisible();
    await expect(page.getByText("OpenRouter Primary", { exact: true })).toBeVisible();
    await expect(page.getByText("openai/o4-mini").first()).toBeVisible();
    await expect(page.getByText("trace-llm-002")).toBeVisible();
    await expect(page.getByText("analysis-preview-v1").first()).toBeVisible();
  });
});

test.describe("Admin: Integrations & Credentials", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/credentials`, (route) => {
      void route.fulfill({ json: mockCredentials });
    });
    await page.route(`**/api/tenants/${tenantId}/credentials/*/test-connection`, (route) => {
      void route.fulfill({ json: { success: true, latency_ms: 42 } });
    });
  });

  test("navigates to Integrations and shows credential list", async ({ page }) => {
    await openShell(page);
    await page.getByRole("button", { name: "Integrations" }).click();
    await expect(page.getByRole("heading", { name: "Integrations & Credentials", level: 1 })).toBeVisible();
    await expect(page.getByText("NPM Token")).toBeVisible();
    await expect(page.getByText("AI API Key")).toBeVisible();
    await expect(page.getByText("Configured").first()).toBeVisible();
    await expect(page.getByText("Not configured")).toBeVisible();
  });

  test("test connection shows OK result", async ({ page }) => {
    await openShell(page);
    await page.getByRole("button", { name: "Integrations" }).click();
    await expect(page.getByText("NPM Token")).toBeVisible();
    await page.getByRole("button", { name: "Test connection for NPM Token" }).click();
    await expect(page.getByText(/OK.*42ms/)).toBeVisible();
  });

  test("delete credential shows confirm dialog", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/credentials/cred-0001`, (route) => {
      if (route.request().method() === "DELETE") {
        void route.fulfill({ status: 204 });
      }
    });

    await openShell(page);
    await page.getByRole("button", { name: "Integrations" }).click();
    await page.getByRole("button", { name: "Delete NPM Token" }).click();
    await expect(page.getByText("Delete?")).toBeVisible();
    await page.getByRole("button", { name: "No" }).click();
    await expect(page.getByText("NPM Token")).toBeVisible();
  });
});

test.describe("Admin: Audit Log", () => {
  test.beforeEach(async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/audit-events**`, (route) => {
      void route.fulfill({ json: mockAuditEvents });
    });
  });

  test("navigates to Audit Log and renders events", async ({ page }) => {
    await openShell(page);
    await page.getByRole("button", { name: "Audit Log" }).click();
    await expect(page.getByRole("heading", { name: "Audit Log", level: 1 })).toBeVisible();
    await expect(page.getByRole("link", { name: "Export CSV" })).toBeVisible();
    await expect(page.getByText("Local Admin")).toBeVisible();
    await expect(page.getByText("platform-admin")).toBeVisible();
    await expect(page.getByText("pkg:npm/lodash@4.17.21")).toBeVisible();
    await expect(page.getByText("system")).toBeVisible();
    await expect(page.getByText("pkg:npm/evil-package@1.0.0")).toBeVisible();
  });

  test("shows empty state when no events", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/audit-events**`, (route) => {
      void route.fulfill({ json: [] });
    });
    await openShell(page);
    await page.getByRole("button", { name: "Audit Log" }).click();
    await expect(page.getByText("No audit events found.")).toBeVisible();
  });

  test("refresh button re-fetches events", async ({ page }) => {
    await openShell(page);
    await page.getByRole("button", { name: "Audit Log" }).click();
    await expect(page.getByText("Local Admin")).toBeVisible();
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(page.getByText("Local Admin")).toBeVisible();
  });

  test("filters by action using filter input", async ({ page }) => {
    await page.route(`**/api/tenants/${tenantId}/audit-events**`, async (route) => {
      const url = new URL(route.request().url());
      const action = url.searchParams.get("action");
      const filtered = action
        ? mockAuditEvents.filter((e) => e.action.includes(action))
        : mockAuditEvents;
      await route.fulfill({ json: filtered });
    });

    await openShell(page);
    await page.getByRole("button", { name: "Audit Log" }).click();
    await page.getByLabel("Action").fill("allow");
    // Wait for debounce + re-query
    await expect(page.getByText("Local Admin")).toBeVisible();
  });
});
