import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DepsDdevPackagesPanel } from "@/components/deps-dev-packages-panel";

const fetchDepsDdevPackagesMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchDepsDdevPackages: (...args: unknown[]) => fetchDepsDdevPackagesMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

const PKG_NPM = {
  purl: "pkg:npm/lodash@4.17.21",
  ecosystem: "npm",
  namespace: undefined,
  package_name: "lodash",
  package_version: "4.17.21",
  licenses: ["MIT"],
  dependency_count: 0,
  source_repo_url: "https://github.com/lodash/lodash",
};

const PKG_PYPI = {
  purl: "pkg:pypi/requests@2.31.0",
  ecosystem: "pypi",
  namespace: undefined,
  package_name: "requests",
  package_version: "2.31.0",
  licenses: ["Apache-2.0"],
  dependency_count: 5,
  source_repo_url: null,
};

const PKG_SCOPED = {
  purl: "pkg:npm/%40types%2Fnode@20.14.0",
  ecosystem: "npm",
  namespace: "@types",
  package_name: "node",
  package_version: "20.14.0",
  licenses: ["MIT"],
  dependency_count: 0,
  source_repo_url: null,
};

function renderPanel(props?: { tenantId?: string; fetchEnabled?: boolean }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <DepsDdevPackagesPanel {...props} />
    </QueryClientProvider>,
  );
}

describe("DepsDdevPackagesPanel", () => {
  beforeEach(() => {
    fetchDepsDdevPackagesMock.mockReset();
  });

  it("shows a loading state while packages are being fetched", () => {
    fetchDepsDdevPackagesMock.mockReturnValue(new Promise(() => {}));
    renderPanel();
    expect(screen.getByText(/loading deps\.dev package data/i)).toBeDefined();
  });

  it("renders a table row for each returned package", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [PKG_NPM, PKG_PYPI],
      total: 2,
      snapshot_taken_at: "2026-05-14T00:00:00Z",
    });

    renderPanel();

    await waitFor(() => {
      expect(screen.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21")).toBeDefined();
      expect(screen.getByTestId("deps-dev-row-pkg:pypi/requests@2.31.0")).toBeDefined();
    });
  });

  it("shows package name, version, ecosystem, license, and dep count", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [PKG_NPM],
      total: 1,
      snapshot_taken_at: null,
    });

    renderPanel();

    await waitFor(() => {
      const row = screen.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21");
      expect(row.textContent).toContain("lodash");
      expect(row.textContent).toContain("4.17.21");
      expect(row.textContent).toContain("npm");
      expect(row.textContent).toContain("MIT");
      expect(row.textContent).toContain("0");
    });
  });

  it("renders a source repo link when source_repo_url is set", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [PKG_NPM],
      total: 1,
      snapshot_taken_at: null,
    });

    renderPanel();

    await waitFor(() => {
      const link = screen.getByRole("link", { name: /repo/i });
      expect(link.getAttribute("href")).toBe("https://github.com/lodash/lodash");
      expect(link.getAttribute("rel")).toContain("noopener");
      expect(link.getAttribute("target")).toBe("_blank");
    });
  });

  it("does not render a source repo link when source_repo_url is null", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [PKG_PYPI],
      total: 1,
      snapshot_taken_at: null,
    });

    renderPanel();

    await waitFor(() => {
      expect(screen.queryByRole("link")).toBeNull();
    });
  });

  it("renders namespace prefix for scoped packages", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [PKG_SCOPED],
      total: 1,
      snapshot_taken_at: null,
    });

    renderPanel();

    await waitFor(() => {
      const row = screen.getByTestId("deps-dev-row-pkg:npm/%40types%2Fnode@20.14.0");
      expect(row.textContent).toContain("@types/");
      expect(row.textContent).toContain("node");
    });
  });

  it("shows an empty state when no packages are returned", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [],
      total: 0,
      snapshot_taken_at: null,
    });

    renderPanel();

    await waitFor(() => {
      expect(screen.getByText(/no deps\.dev package records found/i)).toBeDefined();
    });
  });

  it("shows an error state when the fetch fails", async () => {
    fetchDepsDdevPackagesMock.mockRejectedValue(new Error("upstream unavailable"));

    renderPanel();

    await waitFor(() => {
      expect(screen.getByText(/upstream unavailable/i)).toBeDefined();
    });
  });

  it("shows the snapshot timestamp when provided", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [PKG_NPM],
      total: 1,
      snapshot_taken_at: "2026-05-14T10:00:00Z",
    });

    renderPanel();

    await waitFor(() => {
      expect(screen.getByText(/1 package/i)).toBeDefined();
    });
  });

  it("does not render a link for a javascript: source_repo_url (adversarial feed data)", async () => {
    fetchDepsDdevPackagesMock.mockResolvedValue({
      packages: [
        {
          ...PKG_NPM,
          source_repo_url: "javascript:alert(document.domain)",
        },
      ],
      total: 1,
      snapshot_taken_at: null,
    });

    renderPanel();

    await waitFor(() => {
      const row = screen.getByTestId("deps-dev-row-pkg:npm/lodash@4.17.21");
      expect(row).toBeDefined();
      // Must NOT render an anchor element for non-http(s) URLs.
      expect(screen.queryByRole("link")).toBeNull();
    });
  });

  it("does not fetch when fetchEnabled is false", () => {
    renderPanel({ fetchEnabled: false });
    expect(fetchDepsDdevPackagesMock).not.toHaveBeenCalled();
  });
});
