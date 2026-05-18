import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { IntegrationsPanel } from "@/components/integrations-panel";

const fetchCredentialsMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  deleteCredential: vi.fn(),
  fetchCredentials: (...args: unknown[]) => fetchCredentialsMock(...args),
  getDefaultTenantId: () => "tenant-a",
  testCredentialConnection: vi.fn(),
}));

vi.mock("framer-motion", () => ({
  motion: {
    tr: ({ children, ...props }: React.ComponentProps<"tr">) => <tr {...props}>{children}</tr>,
  },
}));

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <IntegrationsPanel />
    </QueryClientProvider>,
  );
}

describe("IntegrationsPanel", () => {
  beforeEach(() => {
    fetchCredentialsMock.mockReset();
  });

  it("shows webhook placeholders alongside credential metadata", async () => {
    fetchCredentialsMock.mockResolvedValue([]);

    renderPanel();

    expect(screen.getByText("Notification Webhooks")).toBeInTheDocument();
    expect(screen.getByText("Slack")).toBeInTheDocument();
    expect(screen.getByText("PagerDuty")).toBeInTheDocument();
    expect(screen.getByText("Jira")).toBeInTheDocument();
    expect(screen.getAllByText("coming soon")).toHaveLength(3);
    expect(screen.queryByRole("button", { name: /Slack/ })).not.toBeInTheDocument();
    expect(await screen.findByText(/No credentials configured/)).toBeInTheDocument();
  });
});