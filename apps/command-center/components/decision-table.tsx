"use client";

import { useQuery } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type PaginationState,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDownUp, ChevronLeft, ChevronRight, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";

import type { QuarantineQueueItem } from "@aegiscudo/shared-types";
import { purl } from "@aegiscudo/shared-types";

import { fetchArtifactEvidence, fetchQuarantineQueue, getDefaultTenantId } from "@/lib/control-plane";

import { ArtifactEvidenceViewer } from "./artifact-evidence-viewer";
import { HelpTooltip } from "./ui/tooltip";

const columns: ColumnDef<QuarantineQueueItem>[] = [
  {
    header: "Package",
    accessorFn: (row) => purl(row.coordinate),
  },
  {
    header: "Decision",
    accessorKey: "recommended_action",
    cell: ({ getValue }) => {
      const decision = getValue<string>();
      const className = decision.startsWith("BLOCK")
        ? "status-critical"
        : decision.includes("QUARANTINE")
          ? "status-warning"
          : decision === "ALLOW"
            ? "status-safe"
            : "status-info";
      return <span className={className}>{decision}</span>;
    },
  },
  {
    header: "Signals",
    accessorFn: (row) =>
      `${row.evidence_counts.static_reports}/${row.evidence_counts.sandbox_runs}/${row.evidence_counts.ai_explanations}`,
    cell: ({ row }) => {
      const counts = row.original.evidence_counts;
      return (
        <span className="text-(--color-muted)">
          S{counts.static_reports} / X{counts.sandbox_runs} / AI{counts.ai_explanations}
        </span>
      );
    },
  },
  {
    header: "Trace",
    accessorKey: "trace_id",
  },
];

type DecisionTableProps = {
  initialData?: QuarantineQueueItem[];
  tenantId?: string;
  fetchEnabled?: boolean;
};

export function DecisionTable({
  initialData,
  tenantId = getDefaultTenantId(),
  fetchEnabled = true,
}: DecisionTableProps) {
  const queueQuery = useQuery({
    queryKey: ["quarantine-queue", tenantId],
    queryFn: () => fetchQuarantineQueue(tenantId),
    enabled: fetchEnabled && initialData === undefined,
    initialData,
    staleTime: 30_000,
  });
  const data = queueQuery.data ?? [];
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null);
  const [sorting, setSorting] = useState<SortingState>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 5 });

  useEffect(() => {
    setPagination((current) => ({ ...current, pageIndex: 0 }));
  }, [searchQuery, decisionFilter]);

  const filteredData =
    decisionFilter === "all"
      ? data
      : data.filter((item) => item.recommended_action === decisionFilter);

  const table = useReactTable({
    data: filteredData,
    columns,
    state: {
      sorting,
      globalFilter: searchQuery,
      pagination,
    },
    onSortingChange: setSorting,
    onGlobalFilterChange: setSearchQuery,
    onPaginationChange: setPagination,
    globalFilterFn: (row, _columnId, filterValue) => {
      const normalizedFilter = String(filterValue).trim().toLowerCase();
      if (!normalizedFilter) {
        return true;
      }

      const packageValue = purl(row.original.coordinate).toLowerCase();
      const traceValue = row.original.trace_id.toLowerCase();
      const decisionValue = row.original.recommended_action.toLowerCase();
      return (
        packageValue.includes(normalizedFilter)
        || traceValue.includes(normalizedFilter)
        || decisionValue.includes(normalizedFilter)
      );
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  const visibleItems = table.getRowModel().rows.map((row) => row.original);
  const effectiveSelectedArtifactId =
    selectedArtifactId && visibleItems.some((item) => item.artifact_id === selectedArtifactId)
      ? selectedArtifactId
      : (visibleItems[0]?.artifact_id ?? null);

  useEffect(() => {
    if (selectedArtifactId !== effectiveSelectedArtifactId) {
      setSelectedArtifactId(effectiveSelectedArtifactId);
    }
  }, [effectiveSelectedArtifactId, selectedArtifactId]);

  useEffect(() => {
    if (!visibleItems.length) {
      setSelectedArtifactId(null);
    }
  }, [visibleItems.length]);

  const selectedItem = visibleItems.find((item) => item.artifact_id === effectiveSelectedArtifactId) ?? null;
  const evidenceQuery = useQuery({
    queryKey: ["artifact-evidence", tenantId, effectiveSelectedArtifactId],
    queryFn: () => fetchArtifactEvidence(tenantId, effectiveSelectedArtifactId ?? ""),
    enabled: fetchEnabled && Boolean(effectiveSelectedArtifactId),
    staleTime: 30_000,
  });
  const queueError = queueQuery.error instanceof Error ? queueQuery.error.message : null;
  const evidenceError = evidenceQuery.error instanceof Error ? evidenceQuery.error.message : null;
  const decisionOptions = Array.from(new Set(data.map((item) => item.recommended_action))).sort();

  return (
    <section className="glow-panel overflow-hidden" aria-label="Quarantine queue">
      <div className="flex items-center justify-between border-b border-(--color-border) px-4 py-3">
        <h2 className="text-base font-semibold">Quarantine Queue</h2>
        <HelpTooltip content="Decision rows include the technical policy state and trace ID used for audit correlation.">
          <button aria-label="Decision state help" className="rounded-md p-2 text-(--color-accent) hover:bg-white/10">
            <ShieldAlert size={18} />
          </button>
        </HelpTooltip>
      </div>
      <div className="flex flex-col gap-3 border-b border-(--color-border) px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-1 flex-col gap-3 md:flex-row md:items-center">
          <label className="flex min-w-0 flex-1 flex-col gap-1 text-xs uppercase tracking-[0.18em] text-(--color-muted)">
            Search queue
            <input
              aria-label="Search quarantine queue"
              className="rounded-lg border border-(--color-border) bg-black/10 px-3 py-2 text-sm normal-case tracking-normal text-(--color-text) outline-none transition focus:border-(--color-accent)"
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Package, decision, or trace"
              type="search"
              value={searchQuery}
            />
          </label>
          <label className="flex min-w-[220px] flex-col gap-1 text-xs uppercase tracking-[0.18em] text-(--color-muted)">
            Decision filter
            <select
              aria-label="Filter quarantine queue by decision"
              className="rounded-lg border border-(--color-border) bg-black/10 px-3 py-2 text-sm normal-case tracking-normal text-(--color-text) outline-none transition focus:border-(--color-accent)"
              onChange={(event) => setDecisionFilter(event.target.value)}
              value={decisionFilter}
            >
              <option value="all">All decisions</option>
              {decisionOptions.map((decision) => (
                <option key={decision} value={decision}>
                  {decision}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-(--color-muted)">
          <label className="flex items-center gap-2 uppercase tracking-[0.18em]">
            Rows
            <select
              aria-label="Rows per page"
              className="rounded-lg border border-(--color-border) bg-black/10 px-2 py-1 text-sm normal-case tracking-normal text-(--color-text) outline-none transition focus:border-(--color-accent)"
              onChange={(event) =>
                setPagination({ pageIndex: 0, pageSize: Number(event.target.value) })
              }
              value={pagination.pageSize}
            >
              {[1, 5, 10, 25].map((pageSize) => (
                <option key={pageSize} value={pageSize}>
                  {pageSize}
                </option>
              ))}
            </select>
          </label>
          <span>
            {table.getFilteredRowModel().rows.length} matching package
            {table.getFilteredRowModel().rows.length === 1 ? "" : "s"}
          </span>
        </div>
      </div>
      {queueQuery.isLoading ? (
        <div className="border-b border-(--color-border) px-4 py-3 text-sm text-(--color-muted)">Loading investigation queue…</div>
      ) : null}
      {queueError ? (
        <div className="border-b border-(--color-border) px-4 py-3 text-sm text-(--color-warning)">
          {queueError}
        </div>
      ) : null}
      <table className="w-full border-collapse text-sm">
        <thead>
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id} className="text-left text-(--color-muted)">
              {headerGroup.headers.map((header) => (
                <th key={header.id} className="px-4 py-3 font-medium">
                  {header.isPlaceholder ? null : header.column.getCanSort() ? (
                    <button
                      className="inline-flex items-center gap-2 rounded-md px-1 py-1 transition hover:bg-white/5"
                      onClick={header.column.getToggleSortingHandler()}
                      type="button"
                    >
                      <span>{flexRender(header.column.columnDef.header, header.getContext())}</span>
                      <ArrowDownUp size={14} />
                    </button>
                  ) : (
                    flexRender(header.column.columnDef.header, header.getContext())
                  )}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.length ? (
            table.getRowModel().rows.map((row) => {
              const isSelected = row.original.artifact_id === effectiveSelectedArtifactId;
              return (
                <tr
                  key={row.id}
                  className={`border-t border-(--color-border) transition hover:bg-white/5 ${
                    isSelected ? "bg-white/8" : ""
                  }`}
                  onClick={() => setSelectedArtifactId(row.original.artifact_id)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-3">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              );
            })
          ) : (
            <tr className="border-t border-(--color-border)">
              <td colSpan={columns.length} className="px-4 py-6 text-(--color-muted)">
                No suspicious artifacts are currently queued for review.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-(--color-border) px-4 py-3 text-sm text-(--color-muted)">
        <span>
          Page {table.getState().pagination.pageIndex + 1} of {Math.max(table.getPageCount(), 1)}
        </span>
        <div className="flex items-center gap-2">
          <button
            aria-label="Previous queue page"
            className="rounded-md border border-(--color-border) p-2 disabled:cursor-not-allowed disabled:opacity-40"
            disabled={!table.getCanPreviousPage()}
            onClick={() => table.previousPage()}
            type="button"
          >
            <ChevronLeft size={16} />
          </button>
          <button
            aria-label="Next queue page"
            className="rounded-md border border-(--color-border) p-2 disabled:cursor-not-allowed disabled:opacity-40"
            disabled={!table.getCanNextPage()}
            onClick={() => table.nextPage()}
            type="button"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
      <ArtifactEvidenceViewer
        item={selectedItem}
        evidence={evidenceQuery.data}
        isLoading={evidenceQuery.isLoading}
        errorMessage={evidenceError}
      />
    </section>
  );
}