import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuditLogPanel } from "@/components/audit-log-panel";

const fetchAuditEventsMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchAuditEvents: (...args: unknown[]) => fetchAuditEventsMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

describe("AuditLogPanel", () => {
  beforeEach(() => {
    fetchAuditEventsMock.mockReset();
  });

  it("renders actor display names and roles when provided by the API", async () => {
    fetchAuditEventsMock.mockResolvedValue([
      {
        id: "audit-1",
        tenant_id: "tenant-a",
        actor: "user/018f4a6f-55d0-7000-8000-000000000011",
        actor_display: "Local Admin",
        actor_roles: ["platform-admin"],
        action: "registry-config.updated",
        resource: "registry-config/proxy/npm-public",
        trace_id: "trace-audit-actor-role",
        occurred_at: "2026-05-10T18:00:00Z",
        metadata: {},
      },
    ]);

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <AuditLogPanel />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("Local Admin")).toBeInTheDocument();
    expect(screen.getByText("platform-admin")).toBeInTheDocument();
    expect(screen.getByText("user/018f4a6f-55d0-7000-8000-000000000011")).toBeInTheDocument();
  });
});