"use client";

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { chartData } from "@/lib/mock-data";

export function RequestTimelineChart() {
  return (
    <div className="h-77.5 min-w-0">
      <ResponsiveContainer width="100%" height="100%" minWidth={320}>
        <AreaChart data={chartData} margin={{ left: 0, right: 12, top: 12, bottom: 0 }}>
          <CartesianGrid stroke="rgba(148, 163, 184, 0.18)" vertical={false} />
          <XAxis dataKey="hour" stroke="var(--color-muted)" />
          <YAxis stroke="var(--color-muted)" />
          <Tooltip
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
  );
}