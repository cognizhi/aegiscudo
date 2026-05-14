"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, RefreshCw, ShieldAlert } from "lucide-react";

import type { IocRecordSummary } from "@aegiscudo/shared-types";

import { fetchIocRecords, getDefaultTenantId } from "@/lib/control-plane";

const DEFAULT_LIMIT = 50;

const INDICATOR_TYPE_COLORS: Record<string, string> = {
  "package-name": "text-red-400",
  "maintainer-identity": "text-orange-400",
  domain: "text-yellow-400",
  ip: "text-amber-400",
  url: "text-purple-400",
  "behavioral-fingerprint": "text-pink-400",
};

function indicatorTypeColor(type: string): string {
  return INDICATOR_TYPE_COLORS[type] ?? "text-(--color-muted)";
}

interface IocRecordsPanelProps {
  tenantId?: string;
  fetchEnabled?: boolean;
}

export function IocRecordsPanel({
  tenantId: tenantIdProp,
  fetchEnabled = true,
}: IocRecordsPanelProps) {
  const tenantId = tenantIdProp ?? getDefaultTenantId();

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["ioc-records", tenantId, DEFAULT_LIMIT],
    queryFn: () => fetchIocRecords(tenantId, { limit: DEFAULT_LIMIT }),
    staleTime: 120_000,
    enabled: fetchEnabled,
  });

  const records: IocRecordSummary[] = data?.records ?? [];
  const snapshotAt = data?.snapshot_taken_at
    ? new Date(data.snapshot_taken_at).toLocaleString()
    : null;
  const total = data?.total ?? 0;

  return (
    <section aria-label="cross-ecosystem IOC records" className="glow-panel overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-(--color-border) px-4 py-3">
        <div className="flex items-center gap-2">
          <ShieldAlert
            aria-hidden="true"
            className="text-(--color-accent)"
            size={16}
          />
          <div>
            <div className="text-sm font-semibold">Cross-Ecosystem IOC Correlation</div>
            <p className="mt-0.5 text-xs text-(--color-muted)">
              Indicators of compromise correlated across OpenSSF Malicious Packages and Package Analysis feeds.
            </p>
          </div>
        </div>
        <button
          aria-label={isFetching ? "Refreshing IOC records" : "Refresh IOC records"}
          className="inline-flex items-center gap-1 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10 disabled:opacity-50"
          disabled={isFetching}
          onClick={() => {
            void refetch();
          }}
          type="button"
        >
          <RefreshCw aria-hidden="true" className={isFetching ? "animate-spin" : ""} size={13} />
          {isFetching ? "Refreshing" : "Refresh"}
        </button>
      </header>

      {snapshotAt ? (
        <div className="border-b border-(--color-border) px-4 py-2 text-xs text-(--color-muted)">
          Snapshot taken {snapshotAt} &mdash; {total.toLocaleString()} record{total !== 1 ? "s" : ""} total
        </div>
      ) : null}

      <div className="p-4">
        {isLoading ? (
          <div aria-busy="true" aria-live="polite" className="py-8 text-center text-sm text-(--color-muted)">
            Loading IOC correlation data…
          </div>
        ) : null}

        {error ? (
          <div role="alert" className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle aria-hidden="true" size={14} />
            {error instanceof Error ? error.message : "Failed to load IOC records"}
          </div>
        ) : null}

        {!isLoading && !error && records.length === 0 ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No IOC records found. Run the feed harvester to populate this view.
          </div>
        ) : null}

        {records.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Cross-ecosystem IOC records</caption>
              <thead>
                <tr className="border-b border-(--color-border)">
                  {["Package", "Ecosystem", "Indicator Type", "Indicator Value", "Version"].map(
                    (h) => (
                      <th
                        key={h}
                        scope="col"
                        className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)"
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {records.map((rec) => (
                  <tr
                    key={rec.id}
                    className="border-b border-(--color-border) align-top"
                    data-testid={`ioc-row-${rec.id}`}
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium text-(--color-text)">
                        {rec.namespace ? `${rec.namespace}/` : ""}
                        {rec.package_name}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-(--color-muted)">{rec.ecosystem}</td>
                    <td className="px-4 py-3">
                      <span className={indicatorTypeColor(rec.indicator_type)}>
                        {rec.indicator_type}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-(--color-text) break-all">
                        {rec.indicator_value}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-(--color-muted)">
                      {rec.package_version ?? <span className="italic text-xs">any</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </section>
  );
}
