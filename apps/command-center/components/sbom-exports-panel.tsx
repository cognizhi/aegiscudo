"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Download, FileJson, RefreshCw } from "lucide-react";
import { useState } from "react";

import {
  downloadTenantSbom,
  fetchTenantSboms,
  getDefaultTenantId,
  type TenantSbomDocument,
} from "@/lib/control-plane";

const DEFAULT_LIST_LIMIT = 12;

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatSbomFormat(format: string): string {
  if (format === "cyclonedx-1.7-json") return "CycloneDX 1.7";
  if (format === "cyclonedx-1.6-json") return "CycloneDX 1.6";
  if (format === "spdx-2.3-json") return "SPDX 2.3";
  return format;
}

function formatCreatedAt(value: string): string {
  return new Date(value).toLocaleString();
}

function ntiaLabel(document: TenantSbomDocument): string {
  if (document.ntia_validation.valid) {
    return "NTIA complete";
  }
  const issueCount = document.ntia_validation.issues.length;
  return `${issueCount} NTIA issue${issueCount === 1 ? "" : "s"}`;
}

function issuePreview(document: TenantSbomDocument): string | null {
  if (document.ntia_validation.valid || document.ntia_validation.issues.length === 0) {
    return null;
  }
  return document.ntia_validation.issues[0] ?? null;
}

export function SbomExportsPanel() {
  const tenantId = getDefaultTenantId();
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const { data = [], isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["tenant-sboms", tenantId, DEFAULT_LIST_LIMIT],
    queryFn: () => fetchTenantSboms(tenantId, { limit: DEFAULT_LIST_LIMIT }),
    staleTime: 30_000,
  });

  async function handleDownload(sbom: TenantSbomDocument) {
    try {
      setDownloadError(null);
      setDownloadingId(sbom.id);
      const downloaded = await downloadTenantSbom(tenantId, sbom.id);
      const objectUrl = window.URL.createObjectURL(downloaded.blob);
      const link = window.document.createElement("a");
      link.href = objectUrl;
      link.download = downloaded.fileName ?? `sbom-${sbom.id}.json`;
      window.document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => {
        window.URL.revokeObjectURL(objectUrl);
      }, 0);
    } catch (download) {
      setDownloadError(
        download instanceof Error ? download.message : "Failed to download SBOM",
      );
    } finally {
      setDownloadingId(null);
    }
  }

  return (
    <section className="glow-panel overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-(--color-border) px-4 py-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold">
            <FileJson size={16} className="text-(--color-accent)" />
            SBOM Exports
          </div>
          <p className="mt-1 text-sm text-(--color-muted)">
            Recent tenant-scoped SBOM documents stored by sbom-service and ready for export.
          </p>
        </div>
        <button
          className="inline-flex items-center gap-1 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10 disabled:opacity-50"
          disabled={isFetching}
          onClick={() => {
            void refetch();
          }}
          type="button"
        >
          <RefreshCw size={13} className={isFetching ? "animate-spin" : ""} />
          Refresh
        </button>
      </header>

      <div className="px-4 py-3 text-xs text-(--color-muted)">
        Showing the latest {DEFAULT_LIST_LIMIT} SBOM documents for the active tenant.
      </div>

      <div className="p-4">
        {isLoading ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">Loading SBOM exports…</div>
        ) : null}

        {error ? (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load SBOM exports"}
          </div>
        ) : null}

        {downloadError ? (
          <div className="mt-3 flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {downloadError}
          </div>
        ) : null}

        {!isLoading && !error && data.length === 0 ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No tenant-scoped SBOM documents are stored yet.
          </div>
        ) : null}

        {data.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-(--color-border)">
                  {[
                    "Source",
                    "Format",
                    "Components",
                    "Size",
                    "Created",
                    "NTIA",
                    "Export",
                  ].map((header) => (
                    <th key={header} className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.map((document) => {
                  const preview = issuePreview(document);
                  return (
                    <tr key={document.id} className="border-b border-(--color-border) align-top">
                      <td className="px-4 py-3">
                        <div className="font-medium text-(--color-text)">{document.source}</div>
                        <div className="mt-1 font-mono text-[11px] text-(--color-muted)">{document.id}</div>
                      </td>
                      <td className="px-4 py-3 text-(--color-muted)">{formatSbomFormat(document.format)}</td>
                      <td className="px-4 py-3 text-(--color-muted)">{document.component_count.toLocaleString()}</td>
                      <td className="px-4 py-3 text-(--color-muted)">{formatBytes(document.storage_size_bytes)}</td>
                      <td className="px-4 py-3 text-(--color-muted)">{formatCreatedAt(document.created_at)}</td>
                      <td className="px-4 py-3">
                        <div className={document.ntia_validation.valid ? "status-safe" : "status-warn"}>
                          {ntiaLabel(document)}
                        </div>
                        {preview ? (
                          <div className="mt-1 max-w-64 text-[11px] text-(--color-muted)">{preview}</div>
                        ) : null}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          aria-label={`Download SBOM for ${document.source}`}
                          className="inline-flex items-center gap-1 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10"
                          disabled={downloadingId === document.id}
                          onClick={() => {
                            void handleDownload(document);
                          }}
                          type="button"
                        >
                          <Download size={13} />
                          {downloadingId === document.id ? "Downloading..." : "Download JSON"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </section>
  );
}