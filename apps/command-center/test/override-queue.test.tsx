import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { OverrideQueue } from "@/components/override-queue";

const fetchOverridesMock = vi.fn();
const submitOverrideDecisionMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchOverrides: (...args: unknown[]) => fetchOverridesMock(...args),
  getDefaultTenantId: () => "tenant-a",
  submitOverrideDecision: (...args: unknown[]) => submitOverrideDecisionMock(...args),
}));

describe("OverrideQueue", () => {
  beforeEach(() => {
    fetchOverridesMock.mockReset();
    submitOverrideDecisionMock.mockReset();
  });

  it("shows inline validation before submitting an override decision", async () => {
    fetchOverridesMock.mockResolvedValue([
      {
        id: "override-1",
        scope: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0", kind: "package", effect: "allow" },
        reason: "Temporary analyst review bypass",
        status: "pending",
        requested_by: "user-1",
        requested_by_display: "Local Admin",
        approved_by: null,
        approved_by_display: null,
        expires_at: "2099-01-01T00:00:00Z",
        created_at: "2098-12-31T00:00:00Z",
      },
    ]);

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <OverrideQueue />
      </QueryClientProvider>,
    );

    await screen.findByText("Temporary analyst review bypass");

    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    expect(await screen.findByText("override reason must contain at least 8 non-whitespace characters")).toBeInTheDocument();
    expect(submitOverrideDecisionMock).not.toHaveBeenCalled();
  });

  it("flags pending overrides that expire within 24 hours", async () => {
    const soonExpiry = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
    const laterExpiry = new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString();
    fetchOverridesMock.mockResolvedValue([
      {
        id: "override-1",
        scope: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0", kind: "package", effect: "allow" },
        reason: "Temporary analyst review bypass",
        status: "pending",
        requested_by: "user-1",
        requested_by_display: "Local Admin",
        approved_by: null,
        approved_by_display: null,
        expires_at: soonExpiry,
        created_at: new Date().toISOString(),
      },
      {
        id: "override-2",
        scope: { ecosystem: "pypi", name: "requestz", version: "99.0.0", kind: "artifact", effect: "allow" },
        reason: "Broader incident investigation window",
        status: "pending",
        requested_by: "user-2",
        requested_by_display: "Security Specialist",
        approved_by: null,
        approved_by_display: null,
        expires_at: laterExpiry,
        created_at: new Date().toISOString(),
      },
    ]);

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <OverrideQueue />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("Under 24h")).toBeInTheDocument();
    expect(screen.getAllByText("Under 24h")).toHaveLength(1);
    expect(screen.getByText("Temporary analyst review bypass").closest("tr")).toContainElement(
      screen.getByText("Under 24h"),
    );
  });

  it("submits a denial note and refreshes the resolved override tab", async () => {
    fetchOverridesMock
      .mockResolvedValueOnce([
        {
          id: "override-1",
          scope: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0", kind: "package", effect: "allow" },
          reason: "Temporary analyst review bypass",
          status: "pending",
          requested_by: "user-1",
          requested_by_display: "Local Admin",
          approved_by: null,
          approved_by_display: null,
          expires_at: "2099-01-01T00:00:00Z",
          created_at: "2098-12-31T00:00:00Z",
        },
      ])
      .mockResolvedValueOnce([
        {
          id: "override-1",
          scope: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0", kind: "package", effect: "allow" },
          reason: "Temporary analyst review bypass",
          status: "denied",
          requested_by: "user-1",
          requested_by_display: "Local Admin",
          approved_by: "reviewer-1",
          approved_by_display: "Security Lead",
          expires_at: "2099-01-01T00:00:00Z",
          created_at: "2098-12-31T00:00:00Z",
        },
      ]);
    submitOverrideDecisionMock.mockResolvedValue({
      id: "override-1",
      status: "denied",
      reason: "Denied for sustained policy concerns.",
      approved_by: "reviewer-1",
      approved_by_display: "Security Lead",
      expires_at: "2099-01-01T00:00:00Z",
      created_at: "2098-12-31T00:00:00Z",
      scope: { ecosystem: "npm", name: "fresh-postinstall", version: "0.1.0", kind: "package", effect: "allow" },
      requested_by: "user-1",
      requested_by_display: "Local Admin",
    });

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <OverrideQueue />
      </QueryClientProvider>,
    );

    await screen.findByText("Temporary analyst review bypass");

    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "Denied for sustained policy concerns." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));

    await waitFor(() => {
      expect(submitOverrideDecisionMock).toHaveBeenCalledWith(
        "tenant-a",
        "override-1",
        "deny",
        { reason: "Denied for sustained policy concerns." },
      );
    });

    expect(await screen.findByRole("button", { name: "Pending (0)" })).toBeInTheDocument();
    const resolvedTab = await screen.findByRole("button", { name: "Resolved (1)" });
    fireEvent.click(resolvedTab);

    expect(await screen.findByText("Security Lead")).toBeInTheDocument();
    expect(screen.getByText("DENIED")).toBeInTheDocument();
  });
});