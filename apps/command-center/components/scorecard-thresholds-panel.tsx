"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, HelpCircle, ShieldCheck } from "lucide-react";
import { useState } from "react";

import type { PolicyProfileSummary, ScorecardCheckThreshold } from "@aegiscudo/shared-types";

import { fetchPolicyScorecardThresholds, fetchPolicyProfiles, getDefaultTenantId } from "@/lib/control-plane";

import { HelpTooltip } from "./ui/tooltip";

type CheckKey = "code_review" | "branch_protection" | "ci_cd" | "maintained" | "signed_releases";

const CHECK_META: Record<
  CheckKey,
  { label: string; description: string; scorecardUrl: string }
> = {
  code_review: {
    label: "Code Review",
    description:
      "Measures whether the project requires code review before merging pull requests. A high score indicates all changes are reviewed, reducing the risk of unreviewed malicious or vulnerable code being merged.",
    scorecardUrl: "https://github.com/ossf/scorecard/blob/main/docs/checks.md#code-review",
  },
  branch_protection: {
    label: "Branch Protection",
    description:
      "Checks whether default and release branches are protected against direct pushes, force-pushes, or deletion. Strong branch protection prevents supply-chain compromise via unauthorized branch writes.",
    scorecardUrl:
      "https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection",
  },
  ci_cd: {
    label: "CI / CD",
    description:
      "Evaluates whether the project uses continuous integration to run automated tests on pull requests. Consistent CI coverage reduces the window for undetected regressions or injected malicious code.",
    scorecardUrl: "https://github.com/ossf/scorecard/blob/main/docs/checks.md#ci-tests",
  },
  maintained: {
    label: "Maintained",
    description:
      "Indicates whether the project is actively maintained based on recent commit activity and issue engagement. Unmaintained projects are more likely to accumulate unpatched vulnerabilities.",
    scorecardUrl: "https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained",
  },
  signed_releases: {
    label: "Signed Releases",
    description:
      "Checks whether release artifacts are cryptographically signed. Signed releases provide tamper-evidence and help prevent distribution of modified or malicious builds.",
    scorecardUrl:
      "https://github.com/ossf/scorecard/blob/main/docs/checks.md#signed-releases",
  },
};

const ACTION_CLASS: Record<string, string> = {
  allow: "status-safe",
  warn: "status-warning",
  block: "status-critical",
  hitl: "status-info",
};

const ACTION_LABEL: Record<string, string> = {
  allow: "Allow",
  warn: "Warn",
  block: "Block",
  hitl: "HITL",
};

function CheckCard({
  checkKey,
  threshold,
}: {
  checkKey: CheckKey;
  threshold: ScorecardCheckThreshold;
}) {
  const meta = CHECK_META[checkKey];
  const actionClass = ACTION_CLASS[threshold.action] ?? "status-info";
  const actionLabel = ACTION_LABEL[threshold.action] ?? threshold.action;

  return (
    <div
      className={`rounded-lg border border-(--color-border) bg-white/4 p-3 transition-opacity ${
        threshold.enabled ? "" : "opacity-50"
      }`}
      data-testid={`scorecard-check-${checkKey}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-1.5 text-sm font-medium">
          {meta.label}
          <HelpTooltip content={meta.description}>
            <button
              aria-label={`${meta.label} check description`}
              className="rounded p-0.5 text-(--color-muted) hover:text-(--color-text)"
              type="button"
            >
              <HelpCircle size={13} />
            </button>
          </HelpTooltip>
        </div>
        <span className={`shrink-0 rounded px-1.5 py-0.5 text-xs font-medium ${actionClass}`}>
          {threshold.enabled ? actionLabel : "disabled"}
        </span>
      </div>
      <div className="mt-3 flex items-end gap-1">
        <span className="text-2xl font-semibold tabular-nums">{threshold.min_score.toFixed(1)}</span>
        <span className="mb-0.5 text-xs text-(--color-muted)">/10 min score</span>
      </div>
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
        <div
          className="h-full rounded-full bg-(--color-accent)"
        style={{ width: `${Math.min(100, Math.max(0, (threshold.min_score / 10) * 100))}%` }}
        />
      </div>
    </div>
  );
}

type ScorecardThresholdsPanelProps = {
  tenantId?: string;
  fetchEnabled?: boolean;
};

const EMPTY_PROFILES: PolicyProfileSummary[] = [];

const SCORECARD_CHECK_KEYS: readonly CheckKey[] = [
  "code_review",
  "branch_protection",
  "ci_cd",
  "maintained",
  "signed_releases",
] as const;

export function ScorecardThresholdsPanel({
  tenantId = getDefaultTenantId(),
  fetchEnabled = true,
}: ScorecardThresholdsPanelProps) {
  const [selectedProfileId, setSelectedProfileId] = useState<string>("");

  const profilesQuery = useQuery({
    queryKey: ["policy-profiles", tenantId],
    queryFn: () => fetchPolicyProfiles(tenantId),
    enabled: fetchEnabled,
    staleTime: 30_000,
  });
  const profiles = profilesQuery.data ?? EMPTY_PROFILES;
  const activeProfileId = selectedProfileId || profiles[0]?.id || "";

  const { data, isLoading, error } = useQuery({
    queryKey: ["scorecard-thresholds", tenantId, activeProfileId],
    queryFn: () => fetchPolicyScorecardThresholds(tenantId, activeProfileId),
    enabled: fetchEnabled && Boolean(activeProfileId),
    staleTime: 60_000,
  });

  return (
    <section className="glow-panel" aria-label="Scorecard policy thresholds">
      <header className="flex flex-wrap items-center gap-2 border-b border-(--color-border) px-4 py-3">
        <ShieldCheck size={16} className="text-(--color-accent)" aria-hidden="true" />
        <div className="flex-1">
          <h2 className="text-sm font-semibold">OpenSSF Scorecard Thresholds</h2>
          <p className="mt-0.5 text-xs text-(--color-muted)">
            Minimum scores and enforcement actions for each check in the active policy version.
          </p>
        </div>
        {profiles.length > 1 && (
          <select
            aria-label="Policy profile for Scorecard thresholds"
            className="rounded-md border border-(--color-border) bg-(--color-surface) px-2 py-1 text-xs"
            onChange={(e) => setSelectedProfileId(e.target.value)}
            value={activeProfileId}
          >
            {profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.name}
              </option>
            ))}
          </select>
        )}
      </header>

      <div className="p-4">
        {profilesQuery.isLoading && (
          <div className="py-6 text-center text-sm text-(--color-muted)">
            Loading Scorecard thresholds…
          </div>
        )}
        {(profilesQuery.error ?? error) && (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {(profilesQuery.error ?? error) instanceof Error
              ? ((profilesQuery.error ?? error) as Error).message
              : "Failed to load Scorecard thresholds"}
          </div>
        )}
        {!profilesQuery.isLoading && !profilesQuery.error && profiles.length === 0 && (
          <div className="py-6 text-center text-sm text-(--color-muted)">
            No policy profiles found.
          </div>
        )}
        {isLoading && (
          <div className="py-6 text-center text-sm text-(--color-muted)">
            Loading Scorecard thresholds…
          </div>
        )}
        {data && (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            {SCORECARD_CHECK_KEYS.map((key) => (
              <CheckCard key={key} checkKey={key} threshold={data[key]} />
            ))}
          </div>
        )}
        {data && (
          <p className="mt-3 text-xs text-(--color-muted)">
            Policy version{" "}
            <span className="font-mono">{data.policy_version_id.slice(0, 8)}</span>. Scores below
            the threshold trigger the displayed action during request-time policy evaluation.
          </p>
        )}
      </div>
    </section>
  );
}
