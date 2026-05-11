"use client";

import type { ArtifactEvidence, QuarantineQueueItem } from "@aegiscudo/shared-types";
import { purl } from "@aegiscudo/shared-types";
import { useState } from "react";

type EvidenceTab = "static" | "sandbox" | "ai" | "audit";

const evidenceTabs: Array<{ id: EvidenceTab; label: string }> = [
  { id: "static", label: "Static Analysis" },
  { id: "sandbox", label: "Sandbox Telemetry" },
  { id: "ai", label: "AI Explanation" },
  { id: "audit", label: "Audit Trail" },
];

type ArtifactEvidenceViewerProps = {
  item: QuarantineQueueItem | null;
  evidence: ArtifactEvidence | undefined;
  isLoading: boolean;
  errorMessage?: string | null;
};

export function ArtifactEvidenceViewer({
  item,
  evidence,
  isLoading,
  errorMessage,
}: ArtifactEvidenceViewerProps) {
  const artifactId = item?.artifact_id ?? "";
  const [tabState, setTabState] = useState<{ artifactId: string; activeTab: EvidenceTab }>({
    artifactId,
    activeTab: "static",
  });
  const activeTab = tabState.artifactId === artifactId ? tabState.activeTab : "static";

  if (!item) {
    return (
      <div className="border-t border-(--color-border) px-4 py-6 text-sm text-(--color-muted)">
        Select a queued artifact to inspect evidence.
      </div>
    );
  }

  const summary = asRecord(item.summary);
  const evidenceSummary = asRecord(summary.evidence);
  const limitations = asStringArray(summary.limitations);
  const observedBehavior = asStringArray(summary.ai_observed_behavior);
  const inference = asStringArray(summary.ai_inference);

  return (
    <div className="border-t border-(--color-border) px-4 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-[0.24em] text-(--color-muted)">Artifact Evidence Viewer</div>
          <h3 className="mt-1 text-base font-semibold">{purl(item.coordinate)}</h3>
          <div className="mt-2 text-xs text-(--color-muted)">Trace {item.trace_id}</div>
          <div className="text-xs text-(--color-muted)">Digest {truncateDigest(item.artifact_sha256)}</div>
        </div>
        <div className="flex flex-wrap gap-2 text-xs">
          <span className="rounded-full border border-(--color-border) px-3 py-1 text-(--color-muted)">
            Confidence {item.confidence}
          </span>
          <span className="rounded-full border border-(--color-border) px-3 py-1 text-(--color-muted)">
            {item.requires_hitl ? "Requires HITL" : "Automated outcome"}
          </span>
          <span className="rounded-full border border-(--color-border) px-3 py-1 text-(--color-text)">
            {item.recommended_action}
          </span>
        </div>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-3">
        <SummaryCard label="Static indicators" value={String(evidenceSummary.static_indicator_count ?? 0)} />
        <SummaryCard label="Sandbox events" value={String(evidenceSummary.sandbox_event_count ?? 0)} />
        <SummaryCard label="Malware matches" value={String(evidenceSummary.malware_match_count ?? 0)} />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <EvidenceList title="Observed behavior" items={observedBehavior} emptyLabel="No observed runtime notes recorded." />
        <EvidenceList title="Inference" items={inference} emptyLabel="No AI inference captured." />
      </div>

      <EvidenceList title="Limitations" items={limitations} emptyLabel="No evidence limitations recorded." className="mt-4" />

      <div className="mt-5 flex flex-wrap gap-2">
        {evidenceTabs.map((tab) => (
          <button
            key={tab.id}
            className={`rounded-full border px-3 py-1.5 text-sm transition ${
              activeTab === tab.id
                ? "border-(--color-accent) bg-(--color-accent)/12 text-(--color-text)"
                : "border-(--color-border) text-(--color-muted) hover:bg-white/6"
            }`}
            onClick={() => setTabState({ artifactId, activeTab: tab.id })}
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="mt-4 rounded-xl border border-(--color-border) bg-white/4 p-3">
        {isLoading ? <div className="text-sm text-(--color-muted)">Loading evidence…</div> : null}
        {errorMessage ? <div className="text-sm text-(--color-warning)">{errorMessage}</div> : null}
        {!isLoading && !errorMessage ? renderTabContent(activeTab, evidence) : null}
      </div>
    </div>
  );
}

function renderTabContent(tab: EvidenceTab, evidence?: ArtifactEvidence) {
  if (!evidence) {
    return <div className="text-sm text-(--color-muted)">Evidence has not been loaded for this artifact.</div>;
  }

  const aiExplanation = asRecord(evidence.ai_explanation);
  const langfuseTraceId = asString(aiExplanation.langfuse_trace_id);
  const langfuseTraceHref = buildLangfuseTraceUrl(langfuseTraceId);

  if (tab === "static") {
    return evidence.static_reports.length ? (
      <StaticReportViewer artifactId={evidence.artifact_id} reports={evidence.static_reports} />
    ) : (
      <div className="text-sm text-(--color-muted)">No static analysis reports are available.</div>
    );
  }

  if (tab === "sandbox") {
    return evidence.sandbox_runs.length ? (
      <SandboxRunViewer artifactId={evidence.artifact_id} runs={evidence.sandbox_runs} />
    ) : (
      <div className="text-sm text-(--color-muted)">No sandbox telemetry is available.</div>
    );
  }

  if (tab === "ai") {
    return (
      <div className="space-y-3">
        <div className="rounded-lg border border-(--color-warning) bg-(--color-warning)/8 px-3 py-2 text-sm text-(--color-text)">
          AI explanation is advisory only and never the sole enforcement authority.
        </div>
        {langfuseTraceId ? (
          <div className="rounded-lg border border-(--color-border) bg-black/10 px-3 py-2 text-sm text-(--color-muted)">
            <span className="mr-2 uppercase tracking-[0.18em] text-[11px]">Langfuse Trace</span>
            {langfuseTraceHref ? (
              <a className="text-(--color-accent) hover:underline" href={langfuseTraceHref} rel="noreferrer" target="_blank">
                {langfuseTraceId}
              </a>
            ) : (
              <span className="font-mono text-xs text-(--color-text)">{langfuseTraceId}</span>
            )}
          </div>
        ) : null}
        {evidence.ai_explanation ? (
          <JsonBlock value={evidence.ai_explanation} />
        ) : (
          <div className="text-sm text-(--color-muted)">No AI explanation is available.</div>
        )}
      </div>
    );
  }

  return evidence.audit_events.length ? (
    <div className="space-y-3">
      {evidence.audit_events.map((event) => (
        <div key={event.id} className="rounded-lg border border-(--color-border) p-3">
          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
            <span className="font-medium">{event.action}</span>
            <span className="text-(--color-muted)">{new Date(event.occurred_at).toLocaleString()}</span>
          </div>
          <div className="mt-1 text-sm text-(--color-muted)">{event.actor} · {event.resource}</div>
          <div className="mt-2">
            <JsonBlock value={event.metadata} compact />
          </div>
        </div>
      ))}
    </div>
  ) : (
    <div className="text-sm text-(--color-muted)">No audit trail entries are available.</div>
  );
}

function SummaryCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-(--color-border) bg-white/5 px-3 py-2">
      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">{label}</div>
      <div className="mt-1 text-xl font-semibold">{value}</div>
    </div>
  );
}

function EvidenceList({
  title,
  items,
  emptyLabel,
  className = "",
}: {
  title: string;
  items: string[];
  emptyLabel: string;
  className?: string;
}) {
  return (
    <div className={`rounded-lg border border-(--color-border) bg-white/4 p-3 ${className}`.trim()}>
      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">{title}</div>
      {items.length ? (
        <ul className="mt-2 space-y-2 text-sm">
          {items.map((item) => (
            <li key={`${title}-${item}`} className="rounded-md bg-white/5 px-3 py-2">
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <div className="mt-2 text-sm text-(--color-muted)">{emptyLabel}</div>
      )}
    </div>
  );
}

function JsonBlock({ value, compact = false }: { value: unknown; compact?: boolean }) {
  return (
    <pre
      className={`overflow-x-auto rounded-md bg-black/20 px-3 py-2 text-xs text-(--color-text) ${
        compact ? "max-h-40" : "max-h-72"
      }`}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function StaticReportViewer({
  artifactId,
  reports,
}: {
  artifactId: string;
  reports: Array<Record<string, unknown>>;
}) {
  const allIndicators = reports.flatMap((report) => getIndicators(report));
  const indicatorsByFile = groupIndicatorsByFile(allIndicators);
  const fileEntries = Array.from(indicatorsByFile.entries()).sort(([left], [right]) => left.localeCompare(right));

  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-[minmax(0,220px)_minmax(0,1fr)]">
        <div className="rounded-lg border border-(--color-border) bg-white/4 p-3">
          <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Files</div>
          <div className="mt-3 space-y-2">
            {fileEntries.map(([filePath, indicators]) => (
              <div key={`${artifactId}-${filePath}`} className="rounded-lg border border-(--color-border) bg-black/10 px-3 py-2">
                <div className="text-sm font-medium text-(--color-text)">{filePath}</div>
                <div className="mt-1 text-xs text-(--color-muted)">{indicators.length} indicators</div>
              </div>
            ))}
          </div>
        </div>
        <div className="space-y-3">
          {reports.map((report, index) => {
            const indicators = getIndicators(report);
            const digest = asRecord(report.artifact_digest);
            return (
              <div key={`${artifactId}-static-${index}`} className="rounded-lg border border-(--color-border) p-3">
                <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                  <span className="font-medium">Static report {index + 1}</span>
                  <span className="text-(--color-muted)">{indicators.length} indicators</span>
                </div>
                <div className="mt-2 grid gap-2 text-xs text-(--color-muted) md:grid-cols-3">
                  <div>Analyzer {asString(report.analyzer_version) ?? "unknown"}</div>
                  <div>Rules {asString(report.rule_set_version) ?? "unknown"}</div>
                  <div>Digest {truncateDigest(asString(digest.hex) ?? artifactId)}</div>
                </div>
                <div className="mt-3 space-y-3">
                  {indicators.map((indicator, indicatorIndex) => (
                    <IndicatorCard
                      key={`${artifactId}-indicator-${index}-${indicatorIndex}`}
                      indicator={indicator}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function SandboxRunViewer({
  artifactId,
  runs,
}: {
  artifactId: string;
  runs: Array<Record<string, unknown>>;
}) {
  return (
    <div className="space-y-3">
      {runs.map((run, index) => {
        const phases = getSandboxPhases(run);
        const sandboxEnvelope = getSandboxEnvelope(run);
        return (
          <div key={`${artifactId}-sandbox-${index}`} className="rounded-lg border border-(--color-border) p-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
              <span className="font-medium">Sandbox run {index + 1}</span>
              <span className="text-(--color-muted)">{phases.length} phases</span>
            </div>
            <div className="mt-2 grid gap-2 text-xs text-(--color-muted) md:grid-cols-3">
              <div>Profile {asString(sandboxEnvelope.profile) ?? "telemetry"}</div>
              <div>State {asString(sandboxEnvelope.state) ?? "captured"}</div>
              <div>
                {formatTimestampIfPresent(
                  asString(sandboxEnvelope.started_at),
                  asString(sandboxEnvelope.completed_at),
                )}
              </div>
            </div>
            <div className="mt-3 space-y-3">
              {phases.map((phase, phaseIndex) => (
                <div key={`${artifactId}-phase-${index}-${phaseIndex}`} className="rounded-lg border border-(--color-border) bg-black/10 p-3">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <div>
                      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Phase</div>
                      <div className="text-sm font-medium text-(--color-text)">{phase.name}</div>
                    </div>
                    <div className="text-xs text-(--color-muted)">{phase.events.length} events</div>
                  </div>
                  <div className="space-y-2">
                    {phase.events.map((event, eventIndex) => (
                      <div key={`${artifactId}-event-${index}-${phaseIndex}-${eventIndex}`} className="rounded-md border border-(--color-border) bg-white/5 px-3 py-2">
                        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                          <span className="font-medium text-(--color-text)">{event.type}</span>
                          <span className={severityClassName(event.severity)}>{event.severity.toUpperCase()}</span>
                        </div>
                        <div className="mt-1 text-sm text-(--color-muted)">{event.summary}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function IndicatorCard({ indicator }: { indicator: StaticIndicator }) {
  const isHighEntropy = indicator.indicatorType === "high-entropy-string";
  const isObfuscated =
    indicator.indicatorType === "hex-escape-sequence" ||
    indicator.indicatorType === "hex-blob" ||
    indicator.indicatorType === "encoded-payload";

  return (
    <details className="rounded-lg border border-(--color-border) bg-black/10 px-3 py-3">
      <summary className="cursor-pointer list-none">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-medium text-(--color-text)">{indicator.indicatorType}</span>
              <span className={severityClassName(indicator.severity)}>{indicator.severity.toUpperCase()}</span>
              {isHighEntropy && (
                <span className="rounded-full border border-(--color-warning)/40 bg-(--color-warning)/10 px-2 py-0.5 text-xs text-(--color-warning)">
                  High Entropy
                </span>
              )}
              {isObfuscated && (
                <span className="rounded-full border border-(--color-warning)/40 bg-(--color-warning)/10 px-2 py-0.5 text-xs text-(--color-warning)">
                  Obfuscated
                </span>
              )}
            </div>
            <div className="mt-1 text-sm text-(--color-muted)">{indicator.summary}</div>
          </div>
          <div className="text-right text-xs text-(--color-muted)">
            <div>{indicator.filePath}</div>
            <div>
              L{indicator.startLine}
              {indicator.endLine !== indicator.startLine ? `-${indicator.endLine}` : ""}
            </div>
          </div>
        </div>
        {isHighEntropy && (
          <div className="mt-2">
            <div className="mb-1 text-xs text-(--color-muted)">Entropy</div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/10">
              <div className="h-full w-[88%] rounded-full bg-(--color-warning)" />
            </div>
          </div>
        )}
        {isObfuscated && (
          <div className="mt-2">
            <div className="mb-1 text-xs text-(--color-muted)">Obfuscation</div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/10">
              <div className="h-full w-[75%] rounded-full bg-(--color-warning)" />
            </div>
          </div>
        )}
      </summary>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div className="rounded-md border border-(--color-border) bg-white/5 px-3 py-2">
          <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Code Slice</div>
          <div className="mt-2 font-mono text-xs text-(--color-text)">
            {indicator.filePath}:{indicator.startLine}
            {indicator.endLine !== indicator.startLine ? `-${indicator.endLine}` : ""}
          </div>
          <div className="mt-2 text-sm text-(--color-muted)">{indicator.summary}</div>
        </div>
        <div className="rounded-md border border-(--color-border) bg-white/5 px-3 py-2">
          <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Attributes</div>
          <div className="mt-2 space-y-1 text-sm text-(--color-muted)">
            <div>Redacted: {indicator.redacted ? "Yes" : "No"}</div>
            <div>Span: {indicator.endLine - indicator.startLine + 1} lines</div>
            {indicator.details.length ? <div>Details: {indicator.details.join(" · ")}</div> : null}
          </div>
        </div>
      </div>
    </details>
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function buildLangfuseTraceUrl(traceId: string | null): string | null {
  if (!traceId) {
    return null;
  }
  const baseUrl = process.env.NEXT_PUBLIC_LANGFUSE_BASE_URL?.replace(/\/$/, "");
  return baseUrl ? `${baseUrl}/trace/${encodeURIComponent(traceId)}` : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

type StaticIndicator = {
  indicatorType: string;
  severity: string;
  filePath: string;
  startLine: number;
  endLine: number;
  redacted: boolean;
  summary: string;
  details: string[];
};

type SandboxPhase = {
  name: string;
  events: Array<{
    type: string;
    severity: string;
    summary: string;
  }>;
};

function getIndicators(report: Record<string, unknown>): StaticIndicator[] {
  const indicators = report.indicators;
  if (!Array.isArray(indicators)) {
    return [];
  }

  return indicators
    .map((indicator) => {
      const record = asRecord(indicator);
      const filePath = asString(record.file_path);
      const indicatorType = asString(record.indicator_type);
      const summary = asString(record.summary);
      const severity = asString(record.severity);
      const startLine = asNumber(record.start_line);
      const endLine = asNumber(record.end_line);
      if (!filePath || !indicatorType || !summary || !severity || !startLine || !endLine) {
        return null;
      }

      const detailsRecord = asRecord(record.details);
      const details = Object.entries(detailsRecord)
        .map(([key, value]) => {
          const stringValue = asString(value);
          return stringValue ? `${key.replaceAll("_", " ")}: ${stringValue}` : null;
        })
        .filter((value): value is string => value !== null);

      return {
        indicatorType,
        severity,
        filePath,
        startLine,
        endLine,
        redacted: record.redacted === true,
        summary,
        details,
      } satisfies StaticIndicator;
    })
    .filter((indicator): indicator is StaticIndicator => indicator !== null);
}

function groupIndicatorsByFile(indicators: StaticIndicator[]): Map<string, StaticIndicator[]> {
  const grouped = new Map<string, StaticIndicator[]>();
  for (const indicator of indicators) {
    const existing = grouped.get(indicator.filePath);
    if (existing) {
      existing.push(indicator);
    } else {
      grouped.set(indicator.filePath, [indicator]);
    }
  }
  return grouped;
}

function getSandboxPhases(run: Record<string, unknown>): SandboxPhase[] {
  const telemetry = getSandboxEnvelope(run);
  const phases = telemetry.phases;
  if (!Array.isArray(phases)) {
    return [];
  }

  return phases
    .map((phase) => {
      const phaseRecord = asRecord(phase);
      const name = asString(phaseRecord.name);
      const events = phaseRecord.events;
      if (!name || !Array.isArray(events)) {
        return null;
      }

      return {
        name,
        events: events
          .map((event) => {
            const eventRecord = asRecord(event);
            const type = asString(eventRecord.type);
            const severity = asString(eventRecord.severity);
            const summary = asString(eventRecord.summary);
            if (!type || !severity || !summary) {
              return null;
            }
            return { type, severity, summary };
          })
          .filter((event): event is SandboxPhase["events"][number] => event !== null),
      } satisfies SandboxPhase;
    })
    .filter((phase): phase is SandboxPhase => phase !== null);
}

function getSandboxEnvelope(run: Record<string, unknown>): Record<string, unknown> {
  const telemetry = asRecord(run.telemetry);
  return Object.keys(telemetry).length ? telemetry : run;
}

function severityClassName(severity: string): string {
  if (severity === "critical" || severity === "denied") {
    return "status-critical";
  }
  if (severity === "high" || severity === "medium" || severity === "pending") {
    return "status-warning";
  }
  if (severity === "low" || severity === "approved") {
    return "status-safe";
  }
  return "status-info";
}

function formatTimestampIfPresent(startedAt: string | null, completedAt: string | null): string {
  if (startedAt && completedAt) {
    return `${new Date(startedAt).toLocaleTimeString()} - ${new Date(completedAt).toLocaleTimeString()}`;
  }
  if (startedAt) {
    return new Date(startedAt).toLocaleString();
  }
  return "No timing metadata";
}

function truncateDigest(digest: string): string {
  if (digest.length <= 18) {
    return digest;
  }
  return `${digest.slice(0, 10)}…${digest.slice(-8)}`;
}