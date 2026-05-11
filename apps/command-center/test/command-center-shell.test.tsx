import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CommandCenterShell } from "@/components/command-center-shell";

vi.mock("@/lib/control-plane", () => ({
  fetchDashboardMetrics: vi.fn(async () => ({
    blocked_packages: 0,
    quarantine_queue_depth: 2,
    active_overrides: 2,
    feed_freshness: "fresh",
    feed_snapshot_age_seconds: 3600,
  })),
  getDefaultTenantId: () => "018f4a6f-55d0-7000-8000-000000000001",
}));

vi.mock("next/dynamic", () => ({
  default: () => () => <div>Timeline chart</div>,
}));

vi.mock("react-grid-layout", () => ({
  ResponsiveGridLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("framer-motion", () => ({
  motion: {
    section: ({ children, ...props }: React.ComponentProps<"section">) => <section {...props}>{children}</section>,
    tr: ({ children, ...props }: React.ComponentProps<"tr">) => <tr {...props}>{children}</tr>,
  },
}));

vi.mock("@/components/ai-providers-panel", () => ({
  AiProvidersPanel: () => <div>AI providers panel</div>,
}));

vi.mock("@/components/audit-log-panel", () => ({
  AuditLogPanel: () => <div>Audit log panel</div>,
}));

vi.mock("@/components/command-palette", () => ({
  CommandPaletteTrigger: () => <button type="button">Command</button>,
}));

vi.mock("@/components/decision-table", () => ({
  DecisionTable: () => <div>Decision table</div>,
}));

vi.mock("@/components/integrations-panel", () => ({
  IntegrationsPanel: () => <div>Integrations panel</div>,
}));

vi.mock("@/components/llm-usage-panel", () => ({
  LlmUsagePanel: () => <div>LLM usage panel</div>,
}));

vi.mock("@/components/override-queue", () => ({
  OverrideQueue: () => <div>Override queue</div>,
}));

vi.mock("@/components/policy-simulator-panel", () => ({
  PolicySimulatorPanel: () => <div>Policy simulator panel</div>,
}));

vi.mock("@/components/registry-proxies-panel", () => ({
  RegistryProxiesPanel: () => <div>Registry proxies panel</div>,
}));

vi.mock("@/components/ui/tooltip", () => ({
  HelpTooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TooltipProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe("CommandCenterShell", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("falls back to the first allowed page when a persona loses access to the active page", async () => {
    render(<CommandCenterShell appVersion="9.9.9-test" />);

    fireEvent.click(screen.getByRole("button", { name: "Audit Log" }));
    expect(screen.getByRole("heading", { name: "Audit Log" })).toBeInTheDocument();
    expect(screen.getByText("Audit log panel")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Persona"), {
      target: { value: "developer" },
    });

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Executive Risk Dashboard" })).toBeInTheDocument();
    });

    expect(screen.queryByRole("button", { name: "Audit Log" })).not.toBeInTheDocument();
    expect(screen.queryByText("Audit log panel")).not.toBeInTheDocument();
    expect(localStorage.getItem("aegiscudo-mock-persona")).toBe("developer");
  });

  it("shows only the sections allowed for the selected persona", async () => {
    render(<CommandCenterShell appVersion="9.9.9-test" />);

    fireEvent.change(screen.getByLabelText("Persona"), {
      target: { value: "ciso-auditor" },
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Audit Log" })).toBeInTheDocument();
    });

    expect(screen.getByRole("button", { name: "Risk" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Integrations" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "LLM Usage" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Evidence" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Simulator" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Registry" })).not.toBeInTheDocument();
  });

  it("shows the injected version in the footer and About panel", () => {
    render(<CommandCenterShell appVersion="9.9.9-test" />);

    expect(screen.getByText("v9.9.9-test")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "About" }));

    const dialog = screen.getByRole("dialog", { name: "Aegiscudo Command Center" });
    expect(dialog).toBeInTheDocument();
    expect(screen.getAllByText("v9.9.9-test")).toHaveLength(2);
    expect(screen.getByText(/NEXT_PUBLIC_APP_VERSION/)).toBeInTheDocument();
  });
});