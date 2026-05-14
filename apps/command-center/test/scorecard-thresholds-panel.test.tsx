import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScorecardThresholdsPanel } from "@/components/scorecard-thresholds-panel";
import { TooltipProvider } from "@/components/ui/tooltip";

const fetchPolicyProfilesMock = vi.fn();
const fetchPolicyScorecardThresholdsMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchPolicyProfiles: (...args: unknown[]) => fetchPolicyProfilesMock(...args),
  fetchPolicyScorecardThresholds: (...args: unknown[]) =>
    fetchPolicyScorecardThresholdsMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

const PROFILE_ALPHA = {
  id: "profile-alpha",
  tenant_id: "tenant-a",
  name: "Alpha Profile",
  mode: "enforce",
  latest_version_id: "version-1",
  latest_version: "1",
  latest_effective_at: "2026-05-01T00:00:00Z",
  created_at: "2026-05-01T00:00:00Z",
  request_count_last_30_days: 120,
};

const PROFILE_BETA = {
  id: "profile-beta",
  tenant_id: "tenant-a",
  name: "Beta Profile",
  mode: "audit",
  latest_version_id: "version-2",
  latest_version: "1",
  latest_effective_at: "2026-05-10T00:00:00Z",
  created_at: "2026-05-10T00:00:00Z",
  request_count_last_30_days: 45,
};

const THRESHOLDS_ALPHA = {
  policy_profile_id: "profile-alpha",
  policy_version_id: "a1b2c3d4-0000-0000-0000-000000000001",
  code_review: { min_score: 7.0, action: "block", enabled: true },
  branch_protection: { min_score: 6.0, action: "warn", enabled: true },
  ci_cd: { min_score: 5.0, action: "warn", enabled: true },
  maintained: { min_score: 4.0, action: "warn", enabled: false },
  signed_releases: { min_score: 0.0, action: "allow", enabled: false },
};

const THRESHOLDS_BETA = {
  policy_profile_id: "profile-beta",
  policy_version_id: "b9c8d7e6-0000-0000-0000-000000000002",
  code_review: { min_score: 9.0, action: "block", enabled: true },
  branch_protection: { min_score: 8.0, action: "block", enabled: true },
  ci_cd: { min_score: 8.0, action: "block", enabled: true },
  maintained: { min_score: 7.0, action: "block", enabled: true },
  signed_releases: { min_score: 5.0, action: "block", enabled: true },
};

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <TooltipProvider>
      <QueryClientProvider client={queryClient}>
        <ScorecardThresholdsPanel />
      </QueryClientProvider>
    </TooltipProvider>,
  );
}

describe("ScorecardThresholdsPanel", () => {
  beforeEach(() => {
    fetchPolicyProfilesMock.mockReset();
    fetchPolicyScorecardThresholdsMock.mockReset();
  });

  it("renders all five check cards with scores and actions for the auto-selected first profile", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);

    renderPanel();

    await waitFor(() => {
      expect(screen.getByTestId("scorecard-check-code_review")).toBeInTheDocument();
    });

    expect(screen.getByTestId("scorecard-check-branch_protection")).toBeInTheDocument();
    expect(screen.getByTestId("scorecard-check-ci_cd")).toBeInTheDocument();
    expect(screen.getByTestId("scorecard-check-maintained")).toBeInTheDocument();
    expect(screen.getByTestId("scorecard-check-signed_releases")).toBeInTheDocument();

    // Code review: min 7.0, block
    const codeReviewCard = screen.getByTestId("scorecard-check-code_review");
    expect(codeReviewCard).toHaveTextContent("7.0");
    expect(codeReviewCard).toHaveTextContent("Block");

    // Branch protection: min 6.0, warn
    const branchCard = screen.getByTestId("scorecard-check-branch_protection");
    expect(branchCard).toHaveTextContent("6.0");
    expect(branchCard).toHaveTextContent("Warn");

    // Maintained: disabled
    const maintainedCard = screen.getByTestId("scorecard-check-maintained");
    expect(maintainedCard).toHaveTextContent("disabled");

    // Signed releases: disabled
    const signedCard = screen.getByTestId("scorecard-check-signed_releases");
    expect(signedCard).toHaveTextContent("disabled");

    // Policy version shown in footer
    expect(screen.getByText(/a1b2c3d4/)).toBeInTheDocument();
  });

  it("shows a loading state while profiles are being fetched", () => {
    fetchPolicyProfilesMock.mockReturnValue(new Promise(() => undefined));
    fetchPolicyScorecardThresholdsMock.mockReturnValue(new Promise(() => undefined));

    renderPanel();

    expect(screen.getByText(/loading scorecard thresholds/i)).toBeInTheDocument();
  });

  it("shows an error state when profile fetch fails", async () => {
    fetchPolicyProfilesMock.mockRejectedValue(new Error("upstream unavailable"));
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);

    renderPanel();

    await waitFor(() => {
      expect(screen.getByText("upstream unavailable")).toBeInTheDocument();
    });
  });

  it("shows 'no policy profiles found' when the tenant has no profiles", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(null);

    renderPanel();

    await waitFor(() => {
      expect(screen.getByText(/no policy profiles found/i)).toBeInTheDocument();
    });
  });

  it("shows an error state when threshold fetch fails", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockRejectedValue(new Error("thresholds unavailable"));

    renderPanel();

    await waitFor(() => {
      expect(screen.getByText("thresholds unavailable")).toBeInTheDocument();
    });
  });

  it("renders a profile selector dropdown when multiple profiles are available", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA, PROFILE_BETA]);
    fetchPolicyScorecardThresholdsMock.mockImplementation(
      async (_tenantId: string, profileId: string) => {
        return profileId === "profile-beta" ? THRESHOLDS_BETA : THRESHOLDS_ALPHA;
      },
    );

    renderPanel();

    await waitFor(() => {
      expect(screen.getByRole("combobox", { name: /policy profile for scorecard/i })).toBeInTheDocument();
      expect(screen.getByTestId("scorecard-check-code_review")).toBeInTheDocument();
    });

    // Initially shows first profile
    expect(screen.getByTestId("scorecard-check-code_review")).toHaveTextContent("7.0");
  });

  it("reloads thresholds when a different profile is selected", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA, PROFILE_BETA]);
    fetchPolicyScorecardThresholdsMock.mockImplementation(
      async (_tenantId: string, profileId: string) => {
        return profileId === "profile-beta" ? THRESHOLDS_BETA : THRESHOLDS_ALPHA;
      },
    );

    renderPanel();

    await waitFor(() => {
      expect(screen.getByTestId("scorecard-check-code_review")).toHaveTextContent("7.0");
    });

    const profileSelect = screen.getByRole("combobox", { name: /policy profile for scorecard/i });
    fireEvent.change(profileSelect, { target: { value: "profile-beta" } });

    await waitFor(() => {
      expect(screen.getByTestId("scorecard-check-code_review")).toHaveTextContent("9.0");
    });
  });

  it("does not render the profile dropdown when only one profile is available", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);

    renderPanel();

    await waitFor(() => {
      expect(screen.getByTestId("scorecard-check-code_review")).toBeInTheDocument();
    });

    expect(
      screen.queryByRole("combobox", { name: /policy profile for scorecard/i }),
    ).not.toBeInTheDocument();
  });

  it("shows scorecard check tooltips with description text", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);

    renderPanel();

    await waitFor(() => {
      expect(screen.getByTestId("scorecard-check-code_review")).toBeInTheDocument();
    });

    // Each check card has a help button for its tooltip
    const helpButtons = screen.getAllByRole("button", { name: /check description/i });
    expect(helpButtons.length).toBe(5);
  });
});
