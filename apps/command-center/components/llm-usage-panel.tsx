"use client";

import type { LlmUsage } from "@aegiscudo/shared-types";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Cpu, ExternalLink } from "lucide-react";

import { fetchLlmUsage, getDefaultTenantId } from "@/lib/control-plane";

function formatInteger(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
}

function formatCost(value: number): string {
  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: value >= 1 ? 2 : 4,
    maximumFractionDigits: 4,
  }).format(value);
}

function formatLatency(value: number | null | undefined): string {
  return typeof value === "number" ? `${Math.round(value)} ms` : "n/a";
}

function validationPassRate(summary: LlmUsage["summary"]): string {
  const denominator = summary.schema_validation_passes + summary.schema_validation_failures;
  if (denominator === 0) {
    return "n/a";
  }
  return `${Math.round((summary.schema_validation_passes / denominator) * 100)}%`;
}

function langfuseTraceUrl(traceId: string | null | undefined): string | null {
  if (!traceId) {
    return null;
  }
  const baseUrl = process.env.NEXT_PUBLIC_LANGFUSE_BASE_URL?.replace(/\/$/, "");
  return baseUrl ? `${baseUrl}/trace/${encodeURIComponent(traceId)}` : null;
}

function MetricCard({ label, value, helper }: { label: string; value: string; helper: string }) {
  return (
    <div className="rounded-lg border border-(--color-border) bg-white/5 p-3">
      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">{label}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      <div className="mt-2 text-xs text-(--color-muted)">{helper}</div>
    </div>
  );
}

export function LlmUsagePanel() {
  const tenantId = getDefaultTenantId();
  const { data, isLoading, error } = useQuery({
    queryKey: ["llm-usage", tenantId],
    queryFn: () => fetchLlmUsage(tenantId),
    staleTime: 30_000,
    retry: false,
  });

  return (
    <section className="glow-panel">
      <header className="flex items-center justify-between border-b border-(--color-border) px-4 py-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Cpu size={16} className="text-(--color-accent)" />
          LLM Usage
        </div>
        <div className="text-xs text-(--color-muted)">Persisted control-plane read model</div>
      </header>

      <div className="space-y-5 p-4">
        {isLoading ? <div className="py-8 text-center text-sm text-(--color-muted)">Loading LLM usage…</div> : null}
        {error ? (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load LLM usage metrics"}
          </div>
        ) : null}
        {data ? (
          <>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
              <MetricCard
                label="Total Calls"
                value={formatInteger(data.summary.total_calls)}
                helper="Persisted successful AI explanation calls recorded by AI Analyst."
              />
              <MetricCard
                label="Total Tokens"
                value={formatInteger(data.summary.total_tokens)}
                helper="Prompt and completion token usage across all providers and models."
              />
              <MetricCard
                label="Estimated Cost"
                value={formatCost(data.summary.estimated_cost)}
                helper="Provider-reported estimated cost captured with each persisted call."
              />
              <MetricCard
                label="Average / P95"
                value={`${formatLatency(data.summary.avg_latency_ms)} / ${formatLatency(data.summary.p95_latency_ms)}`}
                helper="Average and P95 latency across persisted calls."
              />
              <MetricCard
                label="Schema Pass Rate"
                value={validationPassRate(data.summary)}
                helper={`Redaction failures: ${formatInteger(data.summary.redaction_failures)}`}
              />
            </div>

            <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
              <section className="rounded-lg border border-(--color-border) bg-white/4 p-3">
                <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Calls By Day</div>
                {data.calls_by_day.length ? (
                  <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                    {data.calls_by_day.map((bucket) => (
                      <div key={bucket.day} className="rounded-md border border-(--color-border) bg-black/10 px-3 py-2">
                        <div className="text-xs text-(--color-muted)">{bucket.day}</div>
                        <div className="mt-1 text-lg font-semibold">{formatInteger(bucket.total_calls)}</div>
                        <div className="text-xs text-(--color-muted)">{formatInteger(bucket.total_tokens)} tokens</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="mt-3 text-sm text-(--color-muted)">No persisted LLM calls are available yet.</div>
                )}
              </section>

              <section className="rounded-lg border border-(--color-border) bg-white/4 p-3">
                <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Prompt Templates</div>
                {data.prompt_template_versions.length ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {data.prompt_template_versions.map((version) => (
                      <div key={version.prompt_template_version} className="rounded-full border border-(--color-border) px-3 py-1 text-sm text-(--color-text)">
                        {version.prompt_template_version} · {formatInteger(version.total_calls)}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="mt-3 text-sm text-(--color-muted)">No prompt template usage has been persisted yet.</div>
                )}
              </section>
            </div>

            <section className="rounded-lg border border-(--color-border) bg-white/4 p-3">
              <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Usage By Provider And Model</div>
              {data.provider_models.length ? (
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-(--color-border)">
                        {[
                          "Provider",
                          "Model",
                          "Calls",
                          "Prompt",
                          "Completion",
                          "Total",
                          "Cost",
                          "Avg / P95",
                        ].map((heading) => (
                          <th key={heading} className="px-3 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                            {heading}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.provider_models.map((row) => (
                        <tr key={`${row.provider_display_name}-${row.model_id}`} className="border-b border-(--color-border) last:border-b-0">
                          <td className="px-3 py-2">
                            <div className="font-medium">{row.provider_display_name}</div>
                            <div className="text-xs text-(--color-muted)">{row.provider_type}</div>
                          </td>
                          <td className="px-3 py-2 font-mono text-xs text-(--color-muted)">{row.model_id}</td>
                          <td className="px-3 py-2">{formatInteger(row.total_calls)}</td>
                          <td className="px-3 py-2">{formatInteger(row.prompt_tokens)}</td>
                          <td className="px-3 py-2">{formatInteger(row.completion_tokens)}</td>
                          <td className="px-3 py-2">{formatInteger(row.total_tokens)}</td>
                          <td className="px-3 py-2">{formatCost(row.estimated_cost)}</td>
                          <td className="px-3 py-2 text-xs text-(--color-muted)">
                            {formatLatency(row.avg_latency_ms)} / {formatLatency(row.p95_latency_ms)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="mt-3 text-sm text-(--color-muted)">No provider or model usage has been recorded yet.</div>
              )}
            </section>

            <div className="grid gap-4 xl:grid-cols-2">
              <section className="rounded-lg border border-(--color-border) bg-white/4 p-3">
                <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Usage By Analysis Job</div>
                {data.analysis_jobs.length ? (
                  <div className="mt-3 overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-(--color-border)">
                          {["Trace", "Model", "Calls", "Tokens", "Cost", "Last Call"].map((heading) => (
                            <th key={heading} className="px-3 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                              {heading}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {data.analysis_jobs.map((row) => (
                          <tr key={row.analysis_job_id} className="border-b border-(--color-border) last:border-b-0">
                            <td className="px-3 py-2 font-mono text-xs text-(--color-muted)">{row.trace_id}</td>
                            <td className="px-3 py-2 text-xs text-(--color-muted)">{row.model_id}</td>
                            <td className="px-3 py-2">{formatInteger(row.total_calls)}</td>
                            <td className="px-3 py-2">{formatInteger(row.total_tokens)}</td>
                            <td className="px-3 py-2">{formatCost(row.estimated_cost)}</td>
                            <td className="px-3 py-2 text-xs text-(--color-muted)">
                              {new Date(row.last_called_at).toLocaleString()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="mt-3 text-sm text-(--color-muted)">No analysis-job usage has been persisted yet.</div>
                )}
              </section>

              <section className="rounded-lg border border-(--color-border) bg-white/4 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Failing Traces</div>
                  <div className="text-xs text-(--color-muted)">
                    {formatInteger(data.summary.schema_validation_failures + data.summary.redaction_failures)} issue signals
                  </div>
                </div>
                {data.failing_traces.length ? (
                  <div className="mt-3 space-y-3">
                    {data.failing_traces.map((trace) => {
                      const traceUrl = langfuseTraceUrl(trace.langfuse_trace_id);
                      return (
                        <div key={`${trace.analysis_job_id}-${trace.created_at}`} className="rounded-md border border-(--color-border) bg-black/10 p-3">
                          <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
                            <div>
                              <div className="font-medium">{trace.trace_id}</div>
                              <div className="text-xs text-(--color-muted)">
                                {trace.provider_display_name} · {trace.model_id}
                              </div>
                            </div>
                            <div className="text-xs text-(--color-muted)">{new Date(trace.created_at).toLocaleString()}</div>
                          </div>
                          <div className="mt-2 flex flex-wrap gap-2 text-xs">
                            <span className={`rounded-full border px-2 py-0.5 ${trace.schema_valid ? "status-safe border-green-900/30 bg-green-900/10" : "status-block border-red-900/30 bg-red-900/10"}`}>
                              Schema {trace.schema_valid ? "pass" : "fail"}
                            </span>
                            <span className={`rounded-full border px-2 py-0.5 ${trace.redaction_complete ? "status-safe border-green-900/30 bg-green-900/10" : "status-block border-red-900/30 bg-red-900/10"}`}>
                              Redaction {trace.redaction_complete ? "complete" : "failed"}
                            </span>
                            <span className="rounded-full border border-(--color-border) px-2 py-0.5 text-(--color-muted)">
                              {trace.prompt_template_version}
                            </span>
                            <span className="rounded-full border border-(--color-border) px-2 py-0.5 text-(--color-muted)">
                              {formatLatency(trace.latency_ms)}
                            </span>
                          </div>
                          {trace.langfuse_trace_id ? (
                            <div className="mt-2 text-xs text-(--color-muted)">
                              {traceUrl ? (
                                <a className="inline-flex items-center gap-1 text-(--color-accent) hover:underline" href={traceUrl} rel="noreferrer" target="_blank">
                                  {trace.langfuse_trace_id}
                                  <ExternalLink size={12} />
                                </a>
                              ) : (
                                <span className="font-mono">{trace.langfuse_trace_id}</span>
                              )}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="mt-3 text-sm text-(--color-muted)">No failing schema or redaction traces are recorded.</div>
                )}
              </section>
            </div>
          </>
        ) : null}
      </div>
    </section>
  );
}