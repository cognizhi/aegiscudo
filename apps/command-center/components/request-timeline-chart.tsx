"use client";

import { useQuery } from "@tanstack/react-query";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { fetchRequestTimeline, getDefaultTenantId } from "@/lib/control-plane";

export function RequestTimelineChart() {
  const tenantId = getDefaultTenantId();
  const timelineQuery = useQuery({
    queryKey: ["request-timeline", tenantId],
    queryFn: () => fetchRequestTimeline(tenantId),
    staleTime: 30_000,
  });

  const chartData = (timelineQuery.data ?? []).map((bucket) => ({
    hour: formatBucketHour(bucket.bucket_start),
    allow: bucket.allow,
    warn: bucket.warn,
    quarantine: bucket.quarantine,
    block: bucket.block,
  }));
  const totals = chartData.reduce(
    (summary, bucket) => ({
      allow: summary.allow + bucket.allow,
      warn: summary.warn + bucket.warn,
      quarantine: summary.quarantine + bucket.quarantine,
      block: summary.block + bucket.block,
    }),
    { allow: 0, warn: 0, quarantine: 0, block: 0 },
  );
  const errorMessage = timelineQuery.error instanceof Error ? timelineQuery.error.message : null;

  return (
    <div className="min-w-0">
      <div className="mb-3 flex flex-wrap gap-2 text-xs text-(--color-muted)">
        <span className="rounded-full border border-(--color-border) px-2.5 py-1">Allow {totals.allow}</span>
        <span className="rounded-full border border-(--color-border) px-2.5 py-1">Warn {totals.warn}</span>
        <span className="rounded-full border border-(--color-border) px-2.5 py-1">Quarantine {totals.quarantine}</span>
        <span className="rounded-full border border-(--color-border) px-2.5 py-1">Block {totals.block}</span>
      </div>
      {timelineQuery.isLoading ? <div className="mb-3 text-sm text-(--color-muted)">Loading request timeline…</div> : null}
      {errorMessage ? <div className="mb-3 text-sm text-(--color-warning)">{errorMessage}</div> : null}
      {!timelineQuery.isLoading && !errorMessage && !chartData.length ? (
        <div className="mb-3 text-sm text-(--color-muted)">No request timeline activity is available.</div>
      ) : null}
      <div className="h-77.5 min-w-0">
        <ResponsiveContainer width="100%" height="100%" minWidth={320}>
        <AreaChart data={chartData} margin={{ left: 0, right: 12, top: 12, bottom: 0 }}>
          <CartesianGrid stroke="rgba(148, 163, 184, 0.18)" vertical={false} />
          <XAxis dataKey="hour" stroke="var(--color-muted)" />
          <YAxis stroke="var(--color-muted)" />
          <Tooltip
            labelFormatter={(value) => `Hour ${value}`}
            contentStyle={{
              background: "var(--color-surface-elevated)",
              border: "1px solid var(--color-border)",
              borderRadius: 6,
            }}
          />
          <Area type="monotone" dataKey="allow" stackId="1" stroke="var(--color-safe)" fill="rgba(16, 185, 129, 0.28)" />
          <Area type="monotone" dataKey="warn" stackId="1" stroke="var(--color-warning)" fill="rgba(245, 158, 11, 0.26)" />
          <Area type="monotone" dataKey="quarantine" stackId="1" stroke="var(--color-pending)" fill="rgba(167, 139, 250, 0.24)" />
          <Area type="monotone" dataKey="block" stackId="1" stroke="var(--color-critical)" fill="rgba(220, 38, 38, 0.28)" />
        </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function formatBucketHour(bucketStart: string): string {
  return new Date(bucketStart).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  });
}