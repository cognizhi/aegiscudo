"use client";

import { flexRender, getCoreRowModel, useReactTable, type ColumnDef } from "@tanstack/react-table";
import { ShieldAlert } from "lucide-react";

import type { DecisionSummary } from "@aegiscudo/shared-types";
import { purl } from "@aegiscudo/shared-types";

import { HelpTooltip } from "./ui/tooltip";

const columns: ColumnDef<DecisionSummary>[] = [
  {
    header: "Package",
    accessorFn: (row) => purl(row.coordinate),
  },
  {
    header: "Decision",
    accessorKey: "decision",
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
    header: "Trace",
    accessorKey: "traceId",
  },
];

export function DecisionTable({ data }: { data: DecisionSummary[] }) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });

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
      <table className="w-full border-collapse text-sm">
        <thead>
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id} className="text-left text-(--color-muted)">
              {headerGroup.headers.map((header) => (
                <th key={header.id} className="px-4 py-3 font-medium">
                  {flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr key={row.id} className="border-t border-(--color-border) hover:bg-white/5">
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="px-4 py-3">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}