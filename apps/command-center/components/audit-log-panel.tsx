"use client";

import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { ScrollText, AlertTriangle } from "lucide-react";
import { useState } from "react";

import { fetchAuditEvents, getDefaultTenantId } from "@/lib/control-plane";
import type { InvestigationAuditEvent } from "@aegiscudo/shared-types";

const ACTION_COLORS: Record<string, string> = {
  allow: "status-safe",
  block: "status-block",
  quarantine: "status-warn",
  override_approved: "status-safe",
  override_denied: "status-block",
  override_requested: "status-warn",
  policy_updated: "text-(--color-accent)",
  registry_config_created: "text-(--color-muted)",
  registry_config_updated: "text-(--color-muted)",
  registry_config_deleted: "status-warn",
  credential_created: "text-(--color-muted)",
  credential_deleted: "status-warn",
  emergency_bypass: "status-block",
};

function actionClass(action: string): string {
  for (const [key, cls] of Object.entries(ACTION_COLORS)) {
    if (action.toLowerCase().includes(key)) return cls;
  }
  return "text-(--color-muted)";
}

interface AuditEventRowProps {
  event: InvestigationAuditEvent;
}

function AuditEventRow({ event }: AuditEventRowProps) {
  const [expanded, setExpanded] = useState(false);
  const hasMetadata = event.metadata && Object.keys(event.metadata).length > 0;
  const actorDisplay = (event as InvestigationAuditEvent & { actor_display?: string }).actor_display ?? event.actor ?? "—";
  const actorRoles = (event as InvestigationAuditEvent & { actor_roles?: string[] }).actor_roles ?? [];
  const actorRoleLabel = actorRoles.length > 0 ? actorRoles.join(", ") : "—";
  const showRawActor = Boolean(event.actor && actorDisplay !== event.actor);

  return (
    <>
      <motion.tr
        layout
        className="border-b border-(--color-border) hover:bg-white/3 transition-colors cursor-pointer"
        initial={{ opacity: 0, y: 2 }}
        animate={{ opacity: 1, y: 0 }}
        onClick={() => hasMetadata && setExpanded((v) => !v)}
      >
        <td className="px-4 py-2.5 text-xs text-(--color-muted) font-mono whitespace-nowrap">
          {new Date(event.occurred_at).toLocaleString()}
        </td>
        <td className="px-4 py-2.5 text-xs font-medium font-mono">
          <span className={actionClass(event.action ?? "")}>{event.action}</span>
        </td>
        <td className="px-4 py-2.5 text-xs text-(--color-muted)">
          <div>{actorDisplay}</div>
          {showRawActor && (
            <div className="mt-0.5 font-mono text-[10px] text-(--color-muted)">{event.actor}</div>
          )}
        </td>
        <td className="px-4 py-2.5 text-xs text-(--color-muted)">{actorRoleLabel}</td>
        <td className="px-4 py-2.5 text-xs text-(--color-muted) max-w-48 truncate" title={event.resource ?? ""}>
          {event.resource ?? "—"}
        </td>
        <td className="px-4 py-2.5 text-xs text-(--color-muted) font-mono">
          {event.trace_id ? event.trace_id.slice(0, 8) + "…" : "—"}
        </td>
        <td className="px-4 py-2.5 text-xs">
          {hasMetadata && (
            <button
              className="rounded px-1.5 py-0.5 text-[10px] text-(--color-muted) hover:text-(--color-text) hover:bg-white/10 transition-colors"
              aria-expanded={expanded}
              onClick={(e) => { e.stopPropagation(); setExpanded((v) => !v); }}
            >
              {expanded ? "▲" : "▼"}
            </button>
          )}
        </td>
      </motion.tr>
      {expanded && hasMetadata && (
        <tr className="border-b border-(--color-border) bg-white/2">
          <td colSpan={7} className="px-6 py-2">
            <pre className="text-[11px] text-(--color-muted) font-mono whitespace-pre-wrap break-all overflow-hidden max-h-48">
              {JSON.stringify(event.metadata, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

export function AuditLogPanel() {
  const tenantId = getDefaultTenantId();
  const [actionFilter, setActionFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [limit, setLimit] = useState(50);
  const csvParams = new URLSearchParams();
  if (actionFilter) csvParams.set("action", actionFilter);
  if (actorFilter) csvParams.set("actor", actorFilter);
  if (limit) csvParams.set("limit", String(limit));
  const csvUrl = `/api/tenants/${tenantId}/audit-events/export.csv${csvParams.toString() ? `?${csvParams.toString()}` : ""}`;

  const { data: events = [], isLoading, error, refetch } = useQuery({
    queryKey: ["audit-events", tenantId, actionFilter, actorFilter, limit],
    queryFn: () => {
      const params: { action?: string; actor?: string; limit?: number } = { limit };
      if (actionFilter) params.action = actionFilter;
      if (actorFilter) params.actor = actorFilter;
      return fetchAuditEvents(tenantId, params);
    },
  });

  return (
    <section className="glow-panel">
      <header className="flex items-center justify-between border-b border-(--color-border) px-4 py-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <ScrollText size={16} className="text-(--color-accent)" />
          Audit Log
        </div>
        <div className="flex items-center gap-2">
          <a
            aria-label="Export CSV"
            className="rounded px-2 py-1 text-xs text-(--color-muted) hover:text-(--color-text) hover:bg-white/10 transition-colors"
            download
            href={csvUrl}
          >
            Export CSV
          </a>
          <button
            aria-label="Refresh audit log"
            className="rounded px-2 py-1 text-xs text-(--color-muted) hover:text-(--color-text) hover:bg-white/10 transition-colors"
            onClick={() => void refetch()}
          >
            Refresh
          </button>
        </div>
      </header>

      <div className="flex flex-wrap items-center gap-3 border-b border-(--color-border) px-4 py-2">
        <label className="flex items-center gap-1.5 text-xs text-(--color-muted)">
          Action
          <input
            type="text"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            placeholder="e.g. allow"
            className="rounded border border-(--color-border) bg-white/5 px-2 py-0.5 text-xs text-(--color-text) placeholder:text-(--color-muted) focus:outline-none focus:ring-1 focus:ring-(--color-accent)"
          />
        </label>
        <label className="flex items-center gap-1.5 text-xs text-(--color-muted)">
          Actor
          <input
            type="text"
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            placeholder="user / system"
            className="rounded border border-(--color-border) bg-white/5 px-2 py-0.5 text-xs text-(--color-text) placeholder:text-(--color-muted) focus:outline-none focus:ring-1 focus:ring-(--color-accent)"
          />
        </label>
        <label className="flex items-center gap-1.5 text-xs text-(--color-muted)">
          Limit
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="rounded border border-(--color-border) bg-white/5 px-2 py-0.5 text-xs text-(--color-text) focus:outline-none focus:ring-1 focus:ring-(--color-accent)"
          >
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={250}>250</option>
          </select>
        </label>
      </div>

      <div className="p-4">
        {isLoading && (
          <div className="py-8 text-center text-sm text-(--color-muted)">Loading audit events…</div>
        )}
        {error && (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load audit events"}
          </div>
        )}
        {!isLoading && !error && events.length === 0 && (
          <div className="py-8 text-center text-sm text-(--color-muted)">No audit events found.</div>
        )}
        {events.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-(--color-border)">
                  {["Time", "Action", "Actor", "Role", "Resource", "Trace ID", ""].map((h) => (
                    <th key={h} className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <AuditEventRow key={event.id} event={event} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
