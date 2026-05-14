import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { PolicySimulatorPanel } from "@/components/policy-simulator-panel";

const fetchPolicyProfilesMock = vi.fn();
const simulatePolicyReplayMock = vi.fn();
const fetchPolicyScorecardThresholdsMock = vi.fn();
const fetchTenantOpenVexDocumentsMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchPolicyProfiles: (...args: unknown[]) => fetchPolicyProfilesMock(...args),
  simulatePolicyReplay: (...args: unknown[]) => simulatePolicyReplayMock(...args),
  fetchPolicyScorecardThresholds: (...args: unknown[]) =>
    fetchPolicyScorecardThresholdsMock(...args),
  fetchTenantOpenVexDocuments: (...args: unknown[]) =>
    fetchTenantOpenVexDocumentsMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

const PROFILE_ALPHA = {
  id: "018f4a6f-1111-0000-0000-000000000001",
  tenant_id: "tenant-a",
  name: "Alpha Profile",
  mode: "enforce",
  latest_version_id: "018f4a6f-2222-0000-0000-000000000001",
  latest_version: "5",
  latest_effective_at: "2026-05-01T00:00:00Z",
  created_at: "2026-04-01T00:00:00Z",
  request_count_last_30_days: 200,
};

const THRESHOLDS_ALPHA = {
  policy_profile_id: PROFILE_ALPHA.id,
  policy_version_id: PROFILE_ALPHA.latest_version_id,
  code_review: { min_score: 7.0, action: "block", enabled: true },
  branch_protection: { min_score: 6.0, action: "warn", enabled: true },
  ci_cd: { min_score: 5.0, action: "warn", enabled: false },
  maintained: { min_score: 4.0, action: "warn", enabled: false },
  signed_releases: { min_score: 0.0, action: "allow", enabled: false },
};

const VEX_DOCUMENTS = [
  {
    id: "018f4a6f-aaaa-0000-0000-000000000001",
    tenant_id: "tenant-a",
    source: "manual",
    document_id: "vex-doc-1",
    author: "security@example.com",
    context: "https://openvex.dev/ns",
    version: 1,
    document_timestamp: "2026-05-01T00:00:00Z",
    imported_at: "2026-05-02T00:00:00Z",
    expiry_policy: "never",
    document_digest: "sha256:abc",
    statement_count: 4,
  },
  {
    id: "018f4a6f-bbbb-0000-0000-000000000002",
    tenant_id: "tenant-a",
    source: "manual",
    document_id: "vex-doc-2",
    author: "security@example.com",
    context: "https://openvex.dev/ns",
    version: 1,
    document_timestamp: "2026-05-03T00:00:00Z",
    imported_at: "2026-05-04T00:00:00Z",
    expiry_policy: "never",
    document_digest: "sha256:def",
    statement_count: 7,
  },
];

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <PolicySimulatorPanel />
    </QueryClientProvider>,
  );
}

describe("PolicySimulatorPanel", () => {
  beforeEach(() => {
    fetchPolicyProfilesMock.mockReset();
    simulatePolicyReplayMock.mockReset();
    fetchPolicyScorecardThresholdsMock.mockReset();
    fetchTenantOpenVexDocumentsMock.mockReset();
  });

  it("shows no-profiles empty state when profiles list is empty", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([]);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/No policy profiles are available/i)).toBeDefined();
    });
  });

  it("renders profile select when profiles load", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByRole("combobox", { name: /Target policy profile/i })).toBeDefined();
    });
    // The option label includes name · version · count
    expect(screen.getAllByText(/Alpha Profile/).length).toBeGreaterThanOrEqual(1);
  });

  it("shows Scorecard thresholds in effect when profile is loaded", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByLabelText(/Scorecard thresholds in effect for this simulation/i)).toBeDefined();
    });
    // Code Review and Branch Protection are enabled — should appear
    expect(screen.getByText("Code Review")).toBeDefined();
    expect(screen.getByText("Branch Protection")).toBeDefined();
  });

  it("shows only enabled Scorecard checks, not disabled ones", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("Code Review")).toBeDefined();
    });
    // CI / CD, Maintained, Signed Releases are disabled — should not appear
    expect(screen.queryByText("CI / CD")).toBeNull();
    expect(screen.queryByText("Maintained")).toBeNull();
    expect(screen.queryByText("Signed Releases")).toBeNull();
  });

  it("shows 'no checks enabled' message when all thresholds are disabled", async () => {
    const allDisabled = {
      ...THRESHOLDS_ALPHA,
      code_review: { ...THRESHOLDS_ALPHA.code_review, enabled: false },
      branch_protection: { ...THRESHOLDS_ALPHA.branch_protection, enabled: false },
    };
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(allDisabled);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(
        screen.getByText(/No Scorecard checks are enabled for this profile/i),
      ).toBeDefined();
    });
  });

  it("shows VEX advisory section always", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByLabelText(/VEX suppression status/i)).toBeDefined();
    });
  });

  it("shows 'inactive' message when no VEX documents are imported", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/No OpenVEX documents are imported.*VEX suppression is inactive/i)).toBeDefined();
    });
  });

  it("shows document count, total statement count, and pending note when VEX docs exist", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue(VEX_DOCUMENTS);
    renderPanel();
    // 2 documents, 4 + 7 = 11 statements
    await waitFor(() => {
      const section = screen.getByLabelText(/VEX suppression status/i);
      expect(section.textContent).toContain("2");
      expect(section.textContent).toContain("11");
      expect(section.textContent).toContain("not yet active");
      expect(section.textContent).toContain("component identity matching is pending");
    });
  });

  it("shows singular 'document' for exactly one VEX document", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([VEX_DOCUMENTS[0]]);
    renderPanel();
    await waitFor(() => {
      const section = screen.getByLabelText(/VEX suppression status/i);
      // Should read "1 document imported (4 statements)"
      expect(section.textContent).toMatch(/1\s+document\s+imported/);
    });
  });

  it("shows VEX error message when VEX documents fetch fails", async () => {
    fetchPolicyProfilesMock.mockResolvedValue([PROFILE_ALPHA]);
    fetchPolicyScorecardThresholdsMock.mockResolvedValue(THRESHOLDS_ALPHA);
    fetchTenantOpenVexDocumentsMock.mockRejectedValue(new Error("Network error"));
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/Could not load VEX documents/i)).toBeDefined();
    });
  });
});
