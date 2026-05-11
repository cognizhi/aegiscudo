"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { AlertTriangle, Gauge, RefreshCw, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";

import type {
  PolicyDecisionCounts,
  PolicyProfileSummary,
  PolicySimulationRequest,
} from "@aegiscudo/shared-types";

import {
  fetchPolicyProfiles,
  getDefaultTenantId,
  simulatePolicyReplay,
} from "@/lib/control-plane";

type SimulatorEcosystem = "all" | "npm" | "pypi" | "cargo" | "maven" | "docker-oci" | "generic-http";

const ECOSYSTEM_OPTIONS: Array<{ value: SimulatorEcosystem; label: string }> = [
  { value: "all", label: "All ecosystems" },
  { value: "npm", label: "npm" },
  { value: "pypi", label: "PyPI" },
  { value: "cargo", label: "Cargo" },
  { value: "maven", label: "Maven" },
  { value: "docker-oci", label: "Docker / OCI" },
  { value: "generic-http", label: "Generic HTTP" },
];

const LOOKBACK_OPTIONS = [7, 14, 30] as const;
const EMPTY_PROFILES: PolicyProfileSummary[] = [];

function aggregateCounts(counts: PolicyDecisionCounts) {
  return {
    allow: counts.allow,
    warn:
      counts.allow_with_warning +
      counts.require_hitl_approval +
      counts.fallback_to_approved_candidate,
    quarantine: counts.quarantine_pending_analysis,
    block: counts.block_known_malicious + counts.block_policy_violation,
  };
}

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

function formatRequestedAt(value: string): string {
  return new Date(value).toLocaleString();
}

function profileLabel(profile: PolicyProfileSummary): string {
  return `${profile.name} · ${profile.latest_version} · ${profile.request_count_last_30_days} requests`;
}

function deltaLabel(before: number, after: number): string {
  const delta = after - before;
  if (delta === 0) {
    return "No change";
  }
  return delta > 0 ? `+${delta}` : `${delta}`;
}

export function PolicySimulatorPanel() {
  const tenantId = getDefaultTenantId();
  const [selectedProfileId, setSelectedProfileId] = useState<string>("");
  const [lookbackDays, setLookbackDays] = useState<number>(30);
  const [ecosystem, setEcosystem] = useState<SimulatorEcosystem>("all");

  const profilesQuery = useQuery({
    queryKey: ["policy-profiles", tenantId],
    queryFn: () => fetchPolicyProfiles(tenantId),
    staleTime: 30_000,
  });
  const profiles = profilesQuery.data ?? EMPTY_PROFILES;
  const activeProfileId = selectedProfileId || profiles[0]?.id || "";

  const replayMutation = useMutation({
    mutationFn: (request: PolicySimulationRequest) => simulatePolicyReplay(tenantId, request),
  });

  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.id === activeProfileId) ?? null,
    [activeProfileId, profiles],
  );

  const summary = replayMutation.data
    ? {
        before: aggregateCounts(replayMutation.data.baseline_counts),
        after: aggregateCounts(replayMutation.data.simulated_counts),
      }
    : null;
  const replayResult = replayMutation.data ?? null;

  function handleReplay() {
    if (!activeProfileId) {
      return;
    }
    const request: PolicySimulationRequest = {
      policy_profile_id: activeProfileId,
      lookback_days: lookbackDays,
      limit: 24,
    };
    if (ecosystem !== "all") {
      request.ecosystem = ecosystem;
    }
    replayMutation.mutate(request);
  }

  return (
    <section className="glow-panel overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-(--color-border) px-4 py-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Gauge size={16} className="text-(--color-accent)" />
            Policy Simulator
          </div>
          <p className="mt-1 text-sm text-(--color-muted)">
            Replay the latest request history against a target policy profile without persisting a decision.
          </p>
        </div>
        <button
          className="inline-flex items-center gap-1 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10 disabled:opacity-50"
          disabled={profilesQuery.isFetching}
          onClick={() => {
            void profilesQuery.refetch();
          }}
          type="button"
        >
          <RefreshCw size={13} className={profilesQuery.isFetching ? "animate-spin" : ""} />
          Refresh Profiles
        </button>
      </header>

      <div className="p-4">
        {profilesQuery.isLoading ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">Loading policy profiles…</div>
        ) : null}
        {profilesQuery.error ? (
          <div className="mb-4 flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {profilesQuery.error instanceof Error
              ? profilesQuery.error.message
              : "Failed to load policy profiles"}
          </div>
        ) : null}
        {!profilesQuery.isLoading && !profilesQuery.error && profiles.length === 0 ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No policy profiles are available for replay in this tenant.
          </div>
        ) : null}

        {profiles.length > 0 ? (
          <>
            <div className="grid gap-4 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto]">
              <label className="space-y-2 text-sm">
                <span className="text-(--color-muted)">Target policy profile</span>
                <select
                  aria-label="Target policy profile"
                  className="w-full rounded-md border border-(--color-border) bg-(--color-surface) px-3 py-2 text-sm"
                  onChange={(event) => setSelectedProfileId(event.target.value)}
                  value={activeProfileId}
                >
                  {profiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profileLabel(profile)}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-2 text-sm">
                <span className="text-(--color-muted)">Lookback</span>
                <select
                  aria-label="Lookback window"
                  className="w-full rounded-md border border-(--color-border) bg-(--color-surface) px-3 py-2 text-sm"
                  onChange={(event) => setLookbackDays(Number(event.target.value))}
                  value={lookbackDays}
                >
                  {LOOKBACK_OPTIONS.map((value) => (
                    <option key={value} value={value}>
                      Last {value} days
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-2 text-sm">
                <span className="text-(--color-muted)">Ecosystem</span>
                <select
                  aria-label="Ecosystem"
                  className="w-full rounded-md border border-(--color-border) bg-(--color-surface) px-3 py-2 text-sm"
                  onChange={(event) => setEcosystem(event.target.value as SimulatorEcosystem)}
                  value={ecosystem}
                >
                  {ECOSYSTEM_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>

              <div className="flex items-end">
                <button
                  className="inline-flex items-center gap-2 rounded-md border border-(--color-accent) bg-(--color-accent)/12 px-4 py-2 text-sm font-medium text-(--color-text) hover:bg-(--color-accent)/20 disabled:cursor-not-allowed disabled:opacity-50"
                  disabled={!activeProfileId || replayMutation.isPending}
                  onClick={handleReplay}
                  type="button"
                >
                  <Sparkles size={14} />
                  {replayMutation.isPending ? "Replaying…" : "Run Replay"}
                </button>
              </div>
            </div>

            {selectedProfile ? (
              <div className="mt-4 rounded-md border border-(--color-border) bg-white/4 px-4 py-3 text-sm text-(--color-muted)">
                Targeting <span className="font-medium text-(--color-text)">{selectedProfile.name}</span>
                {" "}in <span className="font-mono">{selectedProfile.mode}</span> mode using snapshot{" "}
                <span className="font-mono">{selectedProfile.latest_version}</span>.
              </div>
            ) : null}

            {replayMutation.error ? (
              <div className="mt-4 flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
                <AlertTriangle size={14} />
                {replayMutation.error instanceof Error
                  ? replayMutation.error.message
                  : "Failed to simulate policy replay"}
              </div>
            ) : null}

            {!replayMutation.data && !replayMutation.isPending ? (
              <div className="mt-6 rounded-md border border-dashed border-(--color-border) px-4 py-8 text-center text-sm text-(--color-muted)">
                Select a target profile and run a replay to compare before and after decisions.
              </div>
            ) : null}

            {summary && replayResult ? (
              <>
                <div className="mt-6 grid gap-4 md:grid-cols-5">
                  <motion.div
                    className="rounded-lg border border-(--color-border) bg-white/4 px-4 py-3"
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                  >
                    <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Replay Scope</div>
                    <div className="mt-2 text-2xl font-semibold">{replayResult.replayed_request_count}</div>
                    <div className="mt-1 text-sm text-(--color-muted)">Requests evaluated</div>
                  </motion.div>
                  <motion.div
                    className="rounded-lg border border-(--color-border) bg-white/4 px-4 py-3"
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.03 }}
                  >
                    <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Changed</div>
                    <div className="mt-2 text-2xl font-semibold">{replayResult.changed_request_count}</div>
                    <div className="mt-1 text-sm text-(--color-muted)">Requests with a different decision</div>
                  </motion.div>
                  {[
                    { label: "Allow", before: summary.before.allow, after: summary.after.allow },
                    { label: "Warn / HITL", before: summary.before.warn, after: summary.after.warn },
                    { label: "Quarantine", before: summary.before.quarantine, after: summary.after.quarantine },
                    { label: "Block", before: summary.before.block, after: summary.after.block },
                  ].map((card, index) => (
                    <motion.div
                      key={card.label}
                      className="rounded-lg border border-(--color-border) bg-white/4 px-4 py-3"
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.05 + index * 0.03 }}
                    >
                      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">{card.label}</div>
                      <div className="mt-2 flex items-end justify-between gap-3">
                        <div>
                          <div className="text-sm text-(--color-muted)">Before {card.before}</div>
                          <div className="text-lg font-semibold">After {card.after}</div>
                        </div>
                        <div className="text-sm font-medium text-(--color-accent)">
                          {deltaLabel(card.before, card.after)}
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>

                <div className="mt-6 overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-(--color-border)">
                        {[
                          "Package",
                          "Requested",
                          "Baseline",
                          "Simulated",
                          "Baseline Rationale",
                          "Simulated Rationale",
                        ].map((heading) => (
                          <th key={heading} className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                            {heading}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {replayResult.items.map((item) => (
                        <motion.tr
                          key={item.package_request_id}
                          className={`border-b border-(--color-border) align-top ${
                            item.changed ? "bg-(--color-accent)/6" : "hover:bg-white/3"
                          }`}
                          initial={{ opacity: 0, y: 4 }}
                          animate={{ opacity: 1, y: 0 }}
                        >
                          <td className="px-4 py-3">
                            <div className="font-medium text-(--color-text)">
                              {item.coordinate.name}
                              {item.coordinate.version ? `@${item.coordinate.version}` : ""}
                            </div>
                            <div className="mt-1 text-xs text-(--color-muted)">
                              {item.coordinate.ecosystem}
                              {item.changed ? " · changed" : " · unchanged"}
                            </div>
                          </td>
                          <td className="px-4 py-3 text-xs text-(--color-muted)">{formatRequestedAt(item.requested_at)}</td>
                          <td className="px-4 py-3">
                            <div className={`text-xs font-medium ${decisionClass(item.baseline_decision)}`}>
                              {item.baseline_decision}
                            </div>
                            <div className="mt-1 text-xs text-(--color-muted)">{item.baseline_policy_profile_name}</div>
                          </td>
                          <td className="px-4 py-3">
                            <div className={`text-xs font-medium ${decisionClass(item.simulated_decision)}`}>
                              {item.simulated_decision}
                            </div>
                            <div className="mt-1 text-xs text-(--color-muted)">{replayResult.target_policy_profile_name}</div>
                          </td>
                          <td className="px-4 py-3 text-xs text-(--color-muted)">
                            {item.baseline_rationale.length ? item.baseline_rationale.join("; ") : "No recorded rationale"}
                          </td>
                          <td className="px-4 py-3 text-xs text-(--color-muted)">
                            {item.simulated_rationale.length ? item.simulated_rationale.join("; ") : "No simulated rationale"}
                          </td>
                        </motion.tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : null}
          </>
        ) : null}
      </div>
    </section>
  );
}