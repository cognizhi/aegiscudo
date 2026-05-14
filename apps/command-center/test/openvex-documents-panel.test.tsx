import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { OpenVexDocumentsPanel } from "@/components/openvex-documents-panel";

const fetchTenantOpenVexDocumentsMock = vi.fn();
const fetchTenantOpenVexDocumentMock = vi.fn();

vi.mock("@/lib/control-plane", () => ({
  fetchTenantOpenVexDocuments: (...args: unknown[]) => fetchTenantOpenVexDocumentsMock(...args),
  fetchTenantOpenVexDocument: (...args: unknown[]) => fetchTenantOpenVexDocumentMock(...args),
  getDefaultTenantId: () => "tenant-a",
}));

describe("OpenVexDocumentsPanel", () => {
  beforeEach(() => {
    fetchTenantOpenVexDocumentsMock.mockReset();
    fetchTenantOpenVexDocumentMock.mockReset();
  });

  it("renders imported OpenVEX documents and selected statement detail", async () => {
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([
      {
        id: "openvex-1",
        tenant_id: "tenant-a",
        source: "fixture-openvex.json",
        document_id: "https://fixtures.aegiscudo.invalid/openvex/acme-2026-001",
        author: "Aegiscudo Fixture Suite",
        context: "https://openvex.dev/ns/v0.2.0",
        version: 1,
        document_timestamp: "2026-05-12T08:00:00Z",
        imported_at: "2026-05-13T10:00:00Z",
        expiry_policy: { mode: "never" },
        document_digest: "a".repeat(64),
        statement_count: 2,
      },
      {
        id: "openvex-2",
        tenant_id: "tenant-a",
        source: "partner-openvex.json",
        document_id: "https://fixtures.aegiscudo.invalid/openvex/partner-2026-004",
        author: "Partner Feed",
        context: "https://openvex.dev/ns/v0.2.0",
        version: 4,
        document_timestamp: "2026-05-13T09:15:00Z",
        imported_at: "2026-05-13T10:30:00Z",
        expiry_policy: { mode: "expires-at", expires_at: "2099-05-13T10:30:00Z" },
        document_digest: "b".repeat(64),
        statement_count: 1,
      },
    ]);

    fetchTenantOpenVexDocumentMock.mockImplementation(async (_tenantId: string, documentId: string) => {
      if (documentId === "openvex-2") {
        return {
          id: "openvex-2",
          tenant_id: "tenant-a",
          source: "partner-openvex.json",
          document_id: "https://fixtures.aegiscudo.invalid/openvex/partner-2026-004",
          author: "Partner Feed",
          context: "https://openvex.dev/ns/v0.2.0",
          version: 4,
          document_timestamp: "2026-05-13T09:15:00Z",
          imported_at: "2026-05-13T10:30:00Z",
          expiry_policy: { mode: "expires-at", expires_at: "2099-05-13T10:30:00Z" },
          document_digest: "b".repeat(64),
          statement_count: 1,
          document: {
            statements: [
              {
                vulnerability: { name: "CVE-2026-2222" },
                products: [{ "@id": "pkg:cargo/cargo-evil@0.1.0" }],
                status: "under_investigation",
                impact_statement: "Cargo artifact still being reviewed by the response team.",
              },
            ],
          },
        };
      }

      return {
        id: "openvex-1",
        tenant_id: "tenant-a",
        source: "fixture-openvex.json",
        document_id: "https://fixtures.aegiscudo.invalid/openvex/acme-2026-001",
        author: "Aegiscudo Fixture Suite",
        context: "https://openvex.dev/ns/v0.2.0",
        version: 1,
        document_timestamp: "2026-05-12T08:00:00Z",
        imported_at: "2026-05-13T10:00:00Z",
        expiry_policy: { mode: "never" },
        document_digest: "a".repeat(64),
        statement_count: 2,
        document: {
          statements: [
            {
              vulnerability: { name: "CVE-2026-0001" },
              products: [{ "@id": "pkg:npm/left-pad@1.3.0" }],
              status: "not_affected",
              justification: "component_not_present",
            },
            {
              vulnerability: { name: "CVE-2026-0002" },
              products: [{ "@id": "pkg:pypi/requests@2.31.0" }],
              status: "fixed",
              action_statement: "Patched in upstream release 2.31.0",
            },
          ],
        },
      };
    });

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <OpenVexDocumentsPanel />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("fixture-openvex.json")).toBeInTheDocument();
    expect(fetchTenantOpenVexDocumentsMock).toHaveBeenCalledWith("tenant-a");
    await waitFor(() =>
      expect(fetchTenantOpenVexDocumentMock).toHaveBeenCalledWith("tenant-a", "openvex-1"),
    );
    expect(screen.getByTestId("openvex-suppression-state")).toHaveTextContent(
      "pending component-level vulnerability correlation",
    );
    expect(screen.getByTestId("openvex-summary-statements-value")).toHaveTextContent(/^2$/);
    expect(screen.getByText("CVE-2026-0001")).toBeInTheDocument();
    expect(screen.getByText("pkg:npm/left-pad@1.3.0")).toBeInTheDocument();
    expect(screen.getByText("component_not_present")).toBeInTheDocument();
    expect(screen.getByText("Patched in upstream release 2.31.0")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /partner-openvex\.json/i }));

    await waitFor(() =>
      expect(fetchTenantOpenVexDocumentMock).toHaveBeenCalledWith("tenant-a", "openvex-2"),
    );
    expect(await screen.findByText("CVE-2026-2222")).toBeInTheDocument();
    expect(screen.getByText("Cargo artifact still being reviewed by the response team.")).toBeInTheDocument();
  });

  it("shows the empty state when no OpenVEX documents are stored", async () => {
    fetchTenantOpenVexDocumentsMock.mockResolvedValue([]);

    const queryClient = new QueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <OpenVexDocumentsPanel />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("No tenant-scoped OpenVEX documents have been imported yet.")).toBeInTheDocument();
  });
});