"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";

import type { OverrideQueueItem, OverrideResponse } from "@aegiscudo/shared-types";

import { fetchOverrides, getDefaultTenantId, submitOverrideDecision } from "@/lib/control-plane";

type OverrideTab = "pending" | "resolved";
type OverrideDecisionAction = "approve" | "deny";

interface OverrideDecisionVariables {
  overrideId: string;
  action: OverrideDecisionAction;
  reason: string;
}

const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const EMPTY_OVERRIDES: OverrideQueueItem[] = [];

export function OverrideQueue() {
  const tenantId = getDefaultTenantId();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<OverrideTab>("pending");
  const [decisionNotes, setDecisionNotes] = useState<Record<string, string>>({});
  const [decisionErrors, setDecisionErrors] = useState<Record<string, string>>({});
  const overridesQuery = useQuery({
    queryKey: ["override-queue", tenantId],
    queryFn: () => fetchOverrides(tenantId),
    staleTime: 30_000,
  });
  const decisionMutation = useMutation({
    mutationFn: ({ overrideId, action, reason }: OverrideDecisionVariables) =>
      submitOverrideDecision(tenantId, overrideId, action, { reason }),
    onError: (error: Error, variables: OverrideDecisionVariables) => {
      setDecisionErrors((current) => ({
        ...current,
        [variables.overrideId]:
          error instanceof Error
            ? error.message
            : "Unable to submit the override decision.",
      }));
    },
    onSuccess: async (_response: OverrideResponse, variables: OverrideDecisionVariables) => {
      setDecisionErrors((current) => omitRecordKey(current, variables.overrideId));
      setDecisionNotes((current) => omitRecordKey(current, variables.overrideId));
      await queryClient.invalidateQueries({ queryKey: ["override-queue", tenantId] });
    },
  });

  const items = overridesQuery.data ?? EMPTY_OVERRIDES;
  const pendingItems = useMemo(
    () => items.filter((item) => item.status === "pending"),
    [items],
  );
  const resolvedItems = useMemo(
    () => items.filter((item) => item.status !== "pending"),
    [items],
  );
  const visibleItems = activeTab === "pending" ? pendingItems : resolvedItems;
  const errorMessage = overridesQuery.error instanceof Error ? overridesQuery.error.message : null;

  function handleDecisionNoteChange(overrideId: string, value: string) {
    setDecisionNotes((current) => ({
      ...current,
      [overrideId]: value,
    }));
    setDecisionErrors((current) => omitRecordKey(current, overrideId));
  }

  function handleDecision(item: OverrideQueueItem, action: OverrideDecisionAction) {
    const reason = decisionNotes[item.id]?.trim() ?? "";
    if (reason.length < 8) {
      setDecisionErrors((current) => ({
        ...current,
        [item.id]: "override reason must contain at least 8 non-whitespace characters",
      }));
      return;
    }

    decisionMutation.mutate({
      overrideId: item.id,
      action,
      reason,
    });
  }

  return (
    <section className="glow-panel overflow-hidden" aria-label="Override queue">
      <div className="flex items-center justify-between border-b border-(--color-border) px-4 py-3">
        <div>
          <h2 className="text-base font-semibold">Override Queue</h2>
          <div className="text-sm text-(--color-muted)">Pending and resolved time-bound exceptions.</div>
        </div>
        <div className="flex gap-2 text-sm">
          <button
            className={tabClassName(activeTab === "pending")}
            onClick={() => setActiveTab("pending")}
            type="button"
          >
            Pending ({pendingItems.length})
          </button>
          <button
            className={tabClassName(activeTab === "resolved")}
            onClick={() => setActiveTab("resolved")}
            type="button"
          >
            Resolved ({resolvedItems.length})
          </button>
        </div>
      </div>
      {overridesQuery.isLoading ? (
        <div className="border-b border-(--color-border) px-4 py-3 text-sm text-(--color-muted)">Loading override queue…</div>
      ) : null}
      {errorMessage ? (
        <div className="border-b border-(--color-border) px-4 py-3 text-sm text-(--color-warning)">{errorMessage}</div>
      ) : null}
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="text-left text-(--color-muted)">
            <th className="px-4 py-3 font-medium">Scope</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Requested By</th>
            <th className="px-4 py-3 font-medium">Expires</th>
            <th className="px-4 py-3 font-medium">Review</th>
          </tr>
        </thead>
        <tbody>
          {visibleItems.length ? (
            visibleItems.map((item) => {
              const expiryState = getExpiryState(item.status, item.expires_at);
              return (
              <tr key={item.id} className="border-t border-(--color-border)">
                <td className="px-4 py-3 align-top">
                  <div className="font-medium text-(--color-text)">{formatOverrideScope(item.scope)}</div>
                  <div className="mt-1 text-xs text-(--color-muted)">{item.reason}</div>
                </td>
                <td className="px-4 py-3 align-top">
                  <span className={statusClassName(item.status)}>{item.status.toUpperCase()}</span>
                </td>
                <td className="px-4 py-3 align-top text-(--color-muted)">
                  {item.requested_by_display ?? item.requested_by ?? "System"}
                </td>
                <td className="px-4 py-3 align-top text-(--color-muted)">
                  <div
                    className={expiryPanelClassName(expiryState)}
                    data-expiry-state={expiryState}
                  >
                    <div>{formatTimestamp(item.expires_at)}</div>
                    <div className={expiryRelativeClassName(expiryState)}>{formatRelativeExpiry(item.expires_at)}</div>
                    {expiryState === "expiring-soon" ? (
                      <div className="mt-2 inline-flex rounded-full border border-(--color-warning) bg-(--color-warning)/12 px-2 py-1 text-[11px] font-medium uppercase tracking-[0.18em] text-(--color-warning)">
                        Under 24h
                      </div>
                    ) : null}
                    {expiryState === "expired" ? (
                      <div className="mt-2 inline-flex rounded-full border border-(--color-critical) bg-(--color-critical)/12 px-2 py-1 text-[11px] font-medium uppercase tracking-[0.18em] text-(--color-critical)">
                        Expired
                      </div>
                    ) : null}
                  </div>
                </td>
                <td className="px-4 py-3 align-top">
                  {item.status === "pending" ? (
                    <div className="space-y-2">
                      <label className="sr-only" htmlFor={`override-review-${item.id}`}>
                        Review note for {formatOverrideScope(item.scope)}
                      </label>
                      <textarea
                        id={`override-review-${item.id}`}
                        className="min-h-20 w-full rounded-lg border border-(--color-border) bg-(--color-surface) px-3 py-2 text-sm text-(--color-text)"
                        onChange={(event) => handleDecisionNoteChange(item.id, event.target.value)}
                        placeholder="Add an approval or denial note (minimum 8 characters)."
                        value={decisionNotes[item.id] ?? ""}
                      />
                      <div className="flex flex-wrap gap-2">
                        <button
                          className="rounded-full border border-(--color-accent) bg-(--color-accent)/12 px-3 py-1 text-(--color-text) disabled:cursor-not-allowed disabled:opacity-60"
                          disabled={decisionMutation.isPending}
                          onClick={() => handleDecision(item, "approve")}
                          type="button"
                        >
                          {isDecisionPending(decisionMutation.variables, decisionMutation.isPending, item.id, "approve")
                            ? "Approving…"
                            : "Approve"}
                        </button>
                        <button
                          className="rounded-full border border-(--color-border) px-3 py-1 text-(--color-muted) disabled:cursor-not-allowed disabled:opacity-60"
                          disabled={decisionMutation.isPending}
                          onClick={() => handleDecision(item, "deny")}
                          type="button"
                        >
                          {isDecisionPending(decisionMutation.variables, decisionMutation.isPending, item.id, "deny")
                            ? "Denying…"
                            : "Deny"}
                        </button>
                      </div>
                      {decisionErrors[item.id] ? (
                        <div className="text-xs text-(--color-warning)">{decisionErrors[item.id]}</div>
                      ) : null}
                    </div>
                  ) : (
                    <div className="text-(--color-muted)">
                      {item.approved_by_display ?? item.approved_by ?? "Reviewed by policy service"}
                    </div>
                  )}
                </td>
              </tr>
            );})
          ) : (
            <tr className="border-t border-(--color-border)">
              <td colSpan={5} className="px-4 py-6 text-(--color-muted)">
                No override requests are currently present in this tab.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}

function tabClassName(active: boolean): string {
  return active
    ? "rounded-full border border-(--color-accent) bg-(--color-accent)/12 px-3 py-1 text-(--color-text)"
    : "rounded-full border border-(--color-border) px-3 py-1 text-(--color-muted)";
}

function statusClassName(status: string): string {
  if (status === "pending") {
    return "status-warning";
  }
  if (status === "approved") {
    return "status-safe";
  }
  if (status === "denied") {
    return "status-critical";
  }
  return "status-info";
}

function formatOverrideScope(scope: OverrideQueueItem["scope"]): string {
  const object = asRecord(scope);
  const ecosystem = typeof object.ecosystem === "string" ? object.ecosystem : "unknown";
  const name = typeof object.name === "string" ? object.name : "override";
  const version = typeof object.version === "string" ? `@${object.version}` : "";
  const kind = typeof object.kind === "string" ? object.kind : "scope";
  const effect = typeof object.effect === "string" ? object.effect : "allow";
  return `${effect} ${kind}: pkg:${ecosystem}/${name}${version}`;
}

function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString();
}

function formatRelativeExpiry(value: string): string {
  const expiresAt = new Date(value).getTime();
  if (!Number.isFinite(expiresAt)) {
    return "Unknown expiry";
  }

  const deltaMs = expiresAt - Date.now();
  const absoluteMs = Math.abs(deltaMs);
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["day", 86_400_000],
    ["hour", 3_600_000],
    ["minute", 60_000],
  ];
  const [unit, factor] = units.find((candidate) => absoluteMs >= candidate[1]) ?? ["minute", 60_000];
  return relativeTimeFormatter.format(Math.round(deltaMs / factor), unit);
}

function getExpiryState(status: string, value: string): "normal" | "expiring-soon" | "expired" {
  if (status !== "pending") {
    return "normal";
  }

  const expiresAt = new Date(value).getTime();
  if (!Number.isFinite(expiresAt)) {
    return "normal";
  }

  const deltaMs = expiresAt - Date.now();
  if (deltaMs <= 0) {
    return "expired";
  }
  if (deltaMs <= 86_400_000) {
    return "expiring-soon";
  }
  return "normal";
}

function expiryPanelClassName(state: "normal" | "expiring-soon" | "expired"): string {
  if (state === "expiring-soon") {
    return "rounded-lg border border-(--color-warning)/50 bg-(--color-warning)/8 px-3 py-2 text-(--color-text)";
  }
  if (state === "expired") {
    return "rounded-lg border border-(--color-critical)/50 bg-(--color-critical)/8 px-3 py-2 text-(--color-text)";
  }
  return "px-0 py-0";
}

function expiryRelativeClassName(state: "normal" | "expiring-soon" | "expired"): string {
  if (state === "expiring-soon") {
    return "mt-1 text-xs text-(--color-warning)";
  }
  if (state === "expired") {
    return "mt-1 text-xs text-(--color-critical)";
  }
  return "mt-1 text-xs text-(--color-muted)";
}

function isDecisionPending(
  mutationVariables: OverrideDecisionVariables | undefined,
  isPending: boolean,
  overrideId: string,
  action: OverrideDecisionAction,
): boolean {
  return (
    isPending &&
    mutationVariables?.overrideId === overrideId &&
    mutationVariables.action === action
  );
}

function omitRecordKey(record: Record<string, string>, key: string): Record<string, string> {
  if (!(key in record)) {
    return record;
  }

  const next = { ...record };
  delete next[key];
  return next;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}