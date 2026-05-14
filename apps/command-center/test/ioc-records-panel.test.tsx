import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { IocRecordsPanel } from "@/components/ioc-records-panel";

const fetchIocRecordsMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchIocRecords: (...args: unknown[]) => fetchIocRecordsMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

const REC_PKG_NAME = {
  id: "aaaaaaaa-0000-0000-0000-000000000001",
  ecosystem: "npm",
  namespace: undefined,
  package_name: "evil-package",
  package_version: "1.0.0",
  indicator_type: "package-name" as const,
  indicator_value: "evil-package",
};

const REC_IDENTITY = {
  id: "aaaaaaaa-0000-0000-0000-000000000002",
  ecosystem: "pypi",
  namespace: undefined,
  package_name: "malicious-lib",
  package_version: undefined,
  indicator_type: "maintainer-identity" as const,
  indicator_value: "bad-actor@example.com",
};

const REC_DOMAIN = {
  id: "aaaaaaaa-0000-0000-0000-000000000003",
  ecosystem: "cargo",
  namespace: undefined,
  package_name: "crate-with-ioc",
  package_version: "0.1.0",
  indicator_type: "domain" as const,
  indicator_value: "malware.example.com",
};

function renderPanel(props?: { tenantId?: string; fetchEnabled?: boolean }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <IocRecordsPanel {...props} />
    </QueryClientProvider>,
  );
}

describe("IocRecordsPanel", () => {
  beforeEach(() => {
    fetchIocRecordsMock.mockReset();
  });

  it("shows loading state while fetching", () => {
    fetchIocRecordsMock.mockReturnValue(new Promise(() => {}));
    renderPanel();
    expect(screen.getByText(/loading ioc correlation data/i)).toBeInTheDocument();
  });

  it("renders rows for returned records", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [REC_PKG_NAME, REC_IDENTITY],
      total: 2,
      snapshot_taken_at: "2024-01-10T12:00:00Z",
    });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByTestId(`ioc-row-${REC_PKG_NAME.id}`)).toBeInTheDocument();
      expect(screen.getByTestId(`ioc-row-${REC_IDENTITY.id}`)).toBeInTheDocument();
    });
  });

  it("shows package name, ecosystem, indicator type and value", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [REC_PKG_NAME],
      total: 1,
      snapshot_taken_at: null,
    });
    renderPanel();
    await waitFor(() => {
      // package_name and indicator_value may both be "evil-package" — use getAllByText
      expect(screen.getAllByText("evil-package").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("npm")).toBeInTheDocument();
      expect(screen.getByText("package-name")).toBeInTheDocument();
    });
  });

  it("shows maintainer-identity indicator value", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [REC_IDENTITY],
      total: 1,
      snapshot_taken_at: null,
    });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("bad-actor@example.com")).toBeInTheDocument();
      expect(screen.getByText("maintainer-identity")).toBeInTheDocument();
    });
  });

  it("shows domain indicator type and value", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [REC_DOMAIN],
      total: 1,
      snapshot_taken_at: null,
    });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("malware.example.com")).toBeInTheDocument();
      expect(screen.getByText("domain")).toBeInTheDocument();
    });
  });

  it("shows 'any' for record with no version", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [REC_IDENTITY],
      total: 1,
      snapshot_taken_at: null,
    });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("any")).toBeInTheDocument();
    });
  });

  it("shows namespace prefix for scoped records", async () => {
    const scoped = {
      ...REC_PKG_NAME,
      id: "aaaaaaaa-0000-0000-0000-000000000099",
      namespace: "@evil",
      package_name: "pkg",
    };
    fetchIocRecordsMock.mockResolvedValue({
      records: [scoped],
      total: 1,
      snapshot_taken_at: null,
    });
    renderPanel();
    await waitFor(() => {
      const row = screen.getByTestId(`ioc-row-${scoped.id}`);
      expect(row.textContent).toContain("@evil/");
      expect(row.textContent).toContain("pkg");
    });
  });

  it("shows empty state when no records", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [],
      total: 0,
      snapshot_taken_at: null,
    });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/no ioc records found/i)).toBeInTheDocument();
    });
  });

  it("shows error state on fetch failure", async () => {
    fetchIocRecordsMock.mockRejectedValue(new Error("network error"));
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/network error/i)).toBeInTheDocument();
    });
  });

  it("shows snapshot timestamp when present", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [REC_PKG_NAME],
      total: 1,
      snapshot_taken_at: "2024-01-10T12:00:00Z",
    });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/snapshot taken/i)).toBeInTheDocument();
    });
  });

  it("does not fetch when fetchEnabled is false", () => {
    renderPanel({ fetchEnabled: false });
    expect(fetchIocRecordsMock).not.toHaveBeenCalled();
    expect(screen.queryByText(/loading/i)).not.toBeInTheDocument();
  });

  it("renders a malicious indicator_value as escaped text, not live HTML", async () => {
    const xssRec = {
      ...REC_PKG_NAME,
      id: "aaaaaaaa-0000-0000-0000-00000000ff01",
      indicator_value: "<script>window.__XSS__=1</script>",
    };
    fetchIocRecordsMock.mockResolvedValue({ records: [xssRec], total: 1, snapshot_taken_at: null });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("<script>window.__XSS__=1</script>")).toBeInTheDocument();
    });
    expect((window as unknown as Record<string, unknown>).__XSS__).toBeUndefined();
  });

  it("applies the correct color class for a known indicator type (package-name → red-400)", async () => {
    fetchIocRecordsMock.mockResolvedValue({ records: [REC_PKG_NAME], total: 1, snapshot_taken_at: null });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText("package-name")).toHaveClass("text-red-400");
    });
  });

  it("uses the muted fallback class for an unrecognised indicator type", async () => {
    const unknownRec = {
      ...REC_PKG_NAME,
      id: "aaaaaaaa-0000-0000-0000-00000000ff02",
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      indicator_type: "unknown-future-type" as any,
    };
    fetchIocRecordsMock.mockResolvedValue({ records: [unknownRec], total: 1, snapshot_taken_at: null });
    renderPanel();
    await waitFor(() => {
      const el = screen.getByText("unknown-future-type");
      expect(el.className).toContain("text-(--color-muted)");
    });
  });

  it("shows singular 'record' when total is 1", async () => {
    fetchIocRecordsMock.mockResolvedValue({
      records: [REC_PKG_NAME],
      total: 1,
      snapshot_taken_at: "2024-01-10T12:00:00Z",
    });
    renderPanel();
    await waitFor(() => {
      expect(screen.getByText(/1 record total/i)).toBeInTheDocument();
    });
  });
});
