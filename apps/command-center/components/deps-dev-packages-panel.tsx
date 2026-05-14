"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ExternalLink, GitBranch, RefreshCw } from "lucide-react";

import type { DepsDdevPackageSummary } from "@aegiscudo/shared-types";

import { fetchDepsDdevPackages, getDefaultTenantId } from "@/lib/control-plane";

const DEFAULT_LIMIT = 50;

const ECOSYSTEM_COLORS: Record<string, string> = {
  npm: "text-green-400",
  pypi: "text-yellow-400",
  cargo: "text-orange-400",
  maven: "text-blue-400",
  "docker-oci": "text-sky-400",
  "generic-http": "text-(--color-muted)",
  githubactions: "text-purple-400",
};

function ecosystemColor(ecosystem: string): string {
  return ECOSYSTEM_COLORS[ecosystem.toLowerCase()] ?? "text-(--color-muted)";
}

function shortPurl(purl: string): string {
  const atIdx = purl.indexOf("@");
  const base = atIdx !== -1 ? purl.slice(0, atIdx) : purl;
  const parts = base.split("/");
  return parts.slice(-2).join("/");
}

interface DepsDdevPackagesPanelProps {
  tenantId?: string;
  fetchEnabled?: boolean;
}

export function DepsDdevPackagesPanel({
  tenantId: tenantIdProp,
  fetchEnabled = true,
}: DepsDdevPackagesPanelProps) {
  const tenantId = tenantIdProp ?? getDefaultTenantId();

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["deps-dev-packages", tenantId, DEFAULT_LIMIT],
    queryFn: () => fetchDepsDdevPackages(tenantId, { limit: DEFAULT_LIMIT }),
    staleTime: 120_000,
    enabled: fetchEnabled,
  });

  const packages: DepsDdevPackageSummary[] = data?.packages ?? [];
  const snapshotAt = data?.snapshot_taken_at
    ? new Date(data.snapshot_taken_at).toLocaleString()
    : null;
  const total = data?.total ?? 0;

  return (
    <section aria-label="deps.dev package intelligence" className="glow-panel overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-(--color-border) px-4 py-3">
        <div className="flex items-center gap-2">
          <GitBranch
            aria-hidden="true"
            className="text-(--color-accent)"
            size={16}
          />
          <div>
            <div className="text-sm font-semibold">deps.dev Package Intelligence</div>
            <p className="mt-0.5 text-xs text-(--color-muted)">
              Open-source package data ingested from deps.dev including licenses and dependency counts.
            </p>
          </div>
        </div>
        <button
          className="inline-flex items-center gap-1 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10 disabled:opacity-50"
          disabled={isFetching}
          onClick={() => {
            void refetch();
          }}
          type="button"
        >
          <RefreshCw className={isFetching ? "animate-spin" : ""} size={13} />
          Refresh
        </button>
      </header>

      {snapshotAt ? (
        <div className="border-b border-(--color-border) px-4 py-2 text-xs text-(--color-muted)">
          Snapshot taken {snapshotAt} &mdash; {total.toLocaleString()} package{total !== 1 ? "s" : ""} total
        </div>
      ) : null}

      <div className="p-4">
        {isLoading ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            Loading deps.dev package data…
          </div>
        ) : null}

        {error ? (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load deps.dev packages"}
          </div>
        ) : null}

        {!isLoading && !error && packages.length === 0 ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No deps.dev package records found. Run the feed harvester to populate this view.
          </div>
        ) : null}

        {packages.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-(--color-border)">
                  {["Package", "Version", "Ecosystem", "Licenses", "Deps", "Source"].map(
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
                {packages.map((pkg) => (
                  <tr
                    key={pkg.purl}
                    className="border-b border-(--color-border) align-top"
                    data-testid={`deps-dev-row-${pkg.purl}`}
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium text-(--color-text)">
                        {pkg.namespace ? `${pkg.namespace}/` : ""}
                        {pkg.package_name}
                      </div>
                      <div className="mt-0.5 font-mono text-[11px] text-(--color-muted)">
                        {shortPurl(pkg.purl)}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-(--color-muted)">
                      {pkg.package_version ?? <span className="italic">unknown</span>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={ecosystemColor(pkg.ecosystem)}>{pkg.ecosystem}</span>
                    </td>
                    <td className="px-4 py-3 text-(--color-muted)">
                      {pkg.licenses.length > 0 ? (
                        <span className="font-mono text-xs">
                          {pkg.licenses.join(", ")}
                        </span>
                      ) : (
                        <span className="italic">unknown</span>
                      )}
                    </td>
                    <td className="px-4 py-3 tabular-nums text-(--color-muted)">
                      {pkg.dependency_count.toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      {pkg.source_repo_url && /^https?:\/\//i.test(pkg.source_repo_url) ? (
                        <a
                          aria-label={`Source repository for ${pkg.package_name}`}
                          className="inline-flex items-center gap-1 text-xs text-(--color-accent) hover:underline"
                          href={pkg.source_repo_url}
                          rel="noopener noreferrer"
                          target="_blank"
                        >
                          Repo
                          <ExternalLink aria-hidden="true" size={11} />
                        </a>
                      ) : (
                        <span className="text-(--color-muted) italic text-xs">—</span>
                      )}
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
