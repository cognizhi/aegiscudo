import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SbomExportsPanel } from "@/components/sbom-exports-panel";

const fetchTenantSbomsMock = vi.fn();
const downloadTenantSbomMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchTenantSboms: (...args: unknown[]) => fetchTenantSbomsMock(...args),
  downloadTenantSbom: (...args: unknown[]) => downloadTenantSbomMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

describe("SbomExportsPanel", () => {
  beforeEach(() => {
    fetchTenantSbomsMock.mockReset();
    downloadTenantSbomMock.mockReset();
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:sbom-download");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders recent tenant SBOMs with download links and NTIA issue previews", async () => {
    fetchTenantSbomsMock.mockResolvedValue([
      {
        id: "sbom-1",
        analysis_job_id: null,
        tenant_id: "tenant-a",
        format: "cyclonedx-1.7-json",
        source: "Cargo.lock",
        component_count: 42,
        storage_uri: "file:///tmp/sbom-1.json",
        storage_sha256: "a".repeat(64),
        storage_size_bytes: 4096,
        created_at: "2026-05-13T18:00:00Z",
        ntia_validation: {
          valid: false,
          issues: ["missing components[0].version"],
        },
      },
    ]);
    downloadTenantSbomMock.mockResolvedValue({
      blob: new Blob(['{"bomFormat":"CycloneDX"}'], { type: "application/json" }),
      fileName: "cargo-lock.json",
      contentType: "application/json",
    });

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <SbomExportsPanel />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("Cargo.lock")).toBeInTheDocument();
    expect(fetchTenantSbomsMock).toHaveBeenCalledWith("tenant-a", { limit: 12 });
    expect(screen.getByText("CycloneDX 1.7")).toBeInTheDocument();
    expect(screen.getByText("1 NTIA issue")).toBeInTheDocument();
    expect(screen.getByText("missing components[0].version")).toBeInTheDocument();
    const downloadButton = screen.getByRole("button", {
      name: "Download SBOM for Cargo.lock",
    });
    fireEvent.click(downloadButton);
    await waitFor(() =>
      expect(downloadTenantSbomMock).toHaveBeenCalledWith("tenant-a", "sbom-1"),
    );
  });

  it("shows the empty state when no stored SBOM documents exist", async () => {
    fetchTenantSbomsMock.mockResolvedValue([]);

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <SbomExportsPanel />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("No tenant-scoped SBOM documents are stored yet.")).toBeInTheDocument();
  });
});