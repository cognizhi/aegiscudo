import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GithubActionsScanResultsPanel } from "@/components/github-actions-scan-results-panel";

const fetchMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchGithubActionsScanResults: (...args: unknown[]) => fetchMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

const RESULT_ALLOW = {
  id: "bbbbbbbb-0000-0000-0000-000000000001",
  tenant_id: "tenant-a",
  policy_profile_id: "cccccccc-0000-0000-0000-000000000001",
  owner: "acme-corp",
  repo: "deploy-pipeline",
  ref: "v1.2.3",
  decision: "ALLOW",
  rationale: ["no blocking policy signal matched"],
  trace_id: "trace-allow-001",
  fallback_ref: undefined,
  scanned_at: "2024-03-15T10:00:00Z",
};

const RESULT_BLOCK = {
  id: "bbbbbbbb-0000-0000-0000-000000000002",
  tenant_id: "tenant-a",
  policy_profile_id: "cccccccc-0000-0000-0000-000000000001",
  owner: "evil-org",
  repo: "compromised-actions",
  ref: "v0.0.1",
  decision: "BLOCK_POLICY_VIOLATION",
  rationale: ["action pinned to mutable tag", "unknown publisher"],
  trace_id: "trace-block-002",
  fallback_ref: undefined,
  scanned_at: "2024-03-15T11:00:00Z",
};

const RESULT_QUARANTINE = {
  id: "bbbbbbbb-0000-0000-0000-000000000003",
  tenant_id: "tenant-a",
  policy_profile_id: "cccccccc-0000-0000-0000-000000000001",
  owner: "unknown-org",
  repo: "new-action",
  ref: "abc1234",
  decision: "QUARANTINE_PENDING_ANALYSIS",
  rationale: ["action analysis pending"],
  trace_id: "trace-quarantine-003",
  fallback_ref: "v1.0.0",
  scanned_at: "2024-03-15T12:00:00Z",
};

function renderPanel(props?: { tenantId?: string; fetchEnabled?: boolean }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <GithubActionsScanResultsPanel {...props} />
    </QueryClientProvider>,
  );
}

describe("GithubActionsScanResultsPanel", () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it("shows loading state while fetching", () => {
    fetchMock.mockReturnValue(new Promise(() => {}));
    renderPanel();
    expect(screen.getByText(/loading scan results/i)).toBeInTheDocument();
  });

  it("renders rows for returned results", async () => {
    fetchMock.mockResolvedValue([RESULT_ALLOW, RESULT_BLOCK]);
    renderPanel();
    await waitFor(() => {
      expect(
        screen.getByTestId(`gha-row-${RESULT_ALLOW.id}`),
      ).toBeInTheDocument();
      expect(
        screen.getByTestId(`gha-row-${RESULT_BLOCK.id}`),
      ).toBeInTheDocument();
    });
  });

  it("shows owner/repo and trace_id for each result", async () => {
    fetchMock.mockResolvedValue([RESULT_ALLOW]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("acme-corp/deploy-pipeline")).toBeInTheDocument();
      expect(screen.getByText("trace-allow-001")).toBeInTheDocument();
    });
  });

  it("shows ref and scanned_at", async () => {
    fetchMock.mockResolvedValue([RESULT_ALLOW]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("v1.2.3")).toBeInTheDocument();
    });
  });

  it("shows fallback_ref when present", async () => {
    fetchMock.mockResolvedValue([RESULT_QUARANTINE]);
    renderPanel();
    await waitFor(() => {
      const row = screen.getByTestId(`gha-row-${RESULT_QUARANTINE.id}`);
      expect(row.textContent).toContain("v1.0.0");
    });
  });

  it("shows BLOCK decision badge with status-block class", async () => {
    fetchMock.mockResolvedValue([RESULT_BLOCK]);
    renderPanel();
    await waitFor(() => {
      const badge = screen
        .getByTestId(`gha-row-${RESULT_BLOCK.id}`)
        .querySelector("[data-decision='BLOCK_POLICY_VIOLATION']");
      expect(badge).not.toBeNull();
      expect(badge?.className).toContain("status-block");
    });
  });

  it("shows ALLOW decision badge with status-safe class", async () => {
    fetchMock.mockResolvedValue([RESULT_ALLOW]);
    renderPanel();
    await waitFor(() => {
      const badge = screen
        .getByTestId(`gha-row-${RESULT_ALLOW.id}`)
        .querySelector("[data-decision='ALLOW']");
      expect(badge).not.toBeNull();
      expect(badge?.className).toContain("status-safe");
    });
  });

  it("shows QUARANTINE decision badge with status-warning class", async () => {
    fetchMock.mockResolvedValue([RESULT_QUARANTINE]);
    renderPanel();
    await waitFor(() => {
      const badge = screen
        .getByTestId(`gha-row-${RESULT_QUARANTINE.id}`)
        .querySelector("[data-decision='QUARANTINE_PENDING_ANALYSIS']");
      expect(badge).not.toBeNull();
      expect(badge?.className).toContain("status-warning");
    });
  });

  it("shows rationale items as list", async () => {
    fetchMock.mockResolvedValue([RESULT_BLOCK]);
    renderPanel();
    await waitFor(() => {
      expect(
        screen.getByText("action pinned to mutable tag"),
      ).toBeInTheDocument();
      expect(screen.getByText("unknown publisher")).toBeInTheDocument();
    });
  });

  it("shows 'none' when rationale is empty", async () => {
    const noRationale = { ...RESULT_ALLOW, rationale: [] };
    fetchMock.mockResolvedValue([noRationale]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("none")).toBeInTheDocument();
    });
  });

  it("shows empty state when results array is empty", async () => {
    fetchMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(
        screen.getByText(/no github actions scan results yet/i),
      ).toBeInTheDocument();
    });
  });

  it("shows error message on fetch failure", async () => {
    fetchMock.mockRejectedValue(new Error("upstream timeout"));
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/upstream timeout/i)).toBeInTheDocument();
    });
  });

  it("does not fetch when fetchEnabled is false", () => {
    renderPanel({ fetchEnabled: false });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.queryByText(/loading/i)).not.toBeInTheDocument();
  });

  it("renders adversarial owner/repo as escaped text, not live HTML", async () => {
    const xssResult = {
      ...RESULT_ALLOW,
      id: "bbbbbbbb-0000-0000-0000-0000000000ff",
      owner: "<script>window.__XSS__=1</script>",
      repo: "safe-repo",
    };
    fetchMock.mockResolvedValue([xssResult]);
    renderPanel();
    await waitFor(() => {
      expect(
        screen.getByText(
          "<script>window.__XSS__=1</script>/safe-repo",
        ),
      ).toBeInTheDocument();
      expect(
        (window as unknown as Record<string, unknown>).__XSS__,
      ).toBeUndefined();
    });
  });
});
