"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, GitBranch, RefreshCw } from "lucide-react";

import type { GithubActionsScanResult } from "@aegiscudo/shared-types";

import { fetchGithubActionsScanResults, getDefaultTenantId } from "@/lib/control-plane";

const DEFAULT_LIMIT = 50;

function decisionClass(decision: string): string {
  if (decision.startsWith("BLOCK")) {
    return "status-block";
  }
  if (decision === "QUARANTINE_PENDING_ANALYSIS") {
    return "status-warning";
  }
  if (decision === "ALLOW") {
    return "status-safe";
  }
  return "status-info";
}

function formatDecisionLabel(decision: string): string {
  return decision.toLowerCase().replace(/_/g, " ");
}

interface GithubActionsScanResultsPanelProps {
  tenantId?: string;
  fetchEnabled?: boolean;
}

export function GithubActionsScanResultsPanel({
  tenantId: tenantIdProp,
  fetchEnabled = true,
}: GithubActionsScanResultsPanelProps) {
  const tenantId = tenantIdProp ?? getDefaultTenantId();

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["github-actions-scan-results", tenantId, DEFAULT_LIMIT],
    queryFn: () => fetchGithubActionsScanResults(tenantId, { limit: DEFAULT_LIMIT }),
    staleTime: 120_000,
    enabled: fetchEnabled,
  });

  const results: GithubActionsScanResult[] = data ?? [];

  return (
    <section
      aria-label="GitHub Actions workflow integrity scan results"
      className="glow-panel overflow-hidden"
    >
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-(--color-border) px-4 py-3">
        <div className="flex items-center gap-2">
          <GitBranch
            aria-hidden="true"
            className="text-(--color-accent)"
            size={16}
          />
          <div>
            <div className="text-sm font-semibold">
              GitHub Actions Workflow Integrity
            </div>
            <p className="mt-0.5 text-xs text-(--color-muted)">
              Scan results from{" "}
              <code className="font-mono">aedo scan github-actions</code>. Run
              the CLI with API config to populate.
            </p>
          </div>
        </div>
        <button
          aria-label={
            isFetching
              ? "Refreshing GitHub Actions scan results"
              : "Refresh GitHub Actions scan results"
          }
          className="inline-flex items-center gap-1 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10 disabled:opacity-50"
          disabled={isFetching}
          onClick={() => {
            void refetch();
          }}
          type="button"
        >
          <RefreshCw
            aria-hidden="true"
            className={isFetching ? "animate-spin" : ""}
            size={13}
          />
          {isFetching ? "Refreshing" : "Refresh"}
        </button>
      </header>

      <div className="p-4">
        {isLoading ? (
          <div
            aria-busy="true"
            aria-live="polite"
            className="py-8 text-center text-sm text-(--color-muted)"
          >
            Loading scan results…
          </div>
        ) : null}

        {error ? (
          <div
            role="alert"
            className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block"
          >
            <AlertTriangle aria-hidden="true" size={14} />
            {error instanceof Error
              ? error.message
              : "Failed to load GitHub Actions scan results"}
          </div>
        ) : null}

        {!isLoading && !error && results.length === 0 ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No GitHub Actions scan results yet. Run{" "}
            <code className="font-mono">aedo scan github-actions</code> with an
            API config pointing to this tenant to populate results.
          </div>
        ) : null}

        {results.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">
                GitHub Actions workflow integrity scan results
              </caption>
              <thead>
                <tr className="border-b border-(--color-border)">
                  {[
                    "Workflow",
                    "Ref",
                    "Decision",
                    "Rationale",
                    "Scanned At",
                  ].map((h) => (
                    <th
                      key={h}
                      scope="col"
                      className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {results.map((result) => (
                  <tr
                    key={result.id}
                    className="border-b border-(--color-border) align-top"
                    data-testid={`gha-row-${result.id}`}
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium text-(--color-text)">
                        {result.owner}/{result.repo}
                      </div>
                      <div className="mt-0.5 font-mono text-xs text-(--color-muted)">
                        {result.trace_id}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-(--color-muted)">
                      {result.ref}
                      {result.fallback_ref ? (
                        <div className="mt-0.5 text-(--color-muted)">
                          → {result.fallback_ref}
                        </div>
                      ) : null}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${decisionClass(result.decision)}`}
                        data-decision={result.decision}
                      >
                        {formatDecisionLabel(result.decision)}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-(--color-muted)">
                      {result.rationale.length > 0 ? (
                        <ul className="list-inside list-disc space-y-0.5">
                          {result.rationale.map((r, i) => (
                            // rationale items have no stable ID; index is acceptable here
                            // eslint-disable-next-line react/no-array-index-key
                            <li key={i}>{r}</li>
                          ))}
                        </ul>
                      ) : (
                        <span className="italic">none</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-(--color-muted)">
                      {new Date(result.scanned_at).toLocaleString()}
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
