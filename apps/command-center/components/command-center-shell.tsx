"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Activity, Boxes, Gauge, KeyRound, LayoutDashboard, Settings, ShieldCheck, Siren } from "lucide-react";
import dynamic from "next/dynamic";
import { useEffect, useMemo, useRef, useState } from "react";
import { ResponsiveGridLayout } from "react-grid-layout";

import { decisions, metrics } from "@/lib/mock-data";

import { DecisionTable } from "./decision-table";
import { HelpTooltip, TooltipProvider } from "./ui/tooltip";

const RequestTimelineChart = dynamic(
  () => import("./request-timeline-chart").then((module) => module.RequestTimelineChart),
  {
    ssr: false,
    loading: () => <div className="h-77.5 rounded-md bg-white/5" aria-label="Loading chart" />,
  },
);

const navigation = [
  { section: "Overview", items: [{ label: "Risk", icon: LayoutDashboard }] },
  { section: "Analysis", items: [{ label: "Evidence", icon: Activity }, { label: "Sandbox", icon: Siren }] },
  { section: "Policy", items: [{ label: "Simulator", icon: Gauge }] },
  { section: "Feeds", items: [{ label: "Registry", icon: Boxes }] },
  { section: "Admin", items: [{ label: "Integrations", icon: KeyRound }, { label: "Settings", icon: Settings }] },
];

export function CommandCenterShell() {
  const queryClient = useMemo(() => new QueryClient(), []);
  const gridRef = useRef<HTMLDivElement>(null);
  const [gridWidth, setGridWidth] = useState(1000);

  useEffect(() => {
    if (!gridRef.current) {
      return undefined;
    }
    const observer = new ResizeObserver(([entry]) => {
      if (entry) {
        setGridWidth(Math.max(320, Math.floor(entry.contentRect.width)));
      }
    });
    observer.observe(gridRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <main className="grid min-h-screen grid-cols-[240px_1fr] bg-(--color-bg)">
          <aside className="border-r border-(--color-border) bg-(--color-surface) px-3 py-4">
            <div className="mb-6 flex items-center gap-2 px-2 text-(--color-accent)">
              <ShieldCheck size={24} />
              <span className="text-lg font-semibold">Aegiscudo</span>
            </div>
            <nav className="space-y-5">
              {navigation.map((group) => (
                <div key={group.section}>
                  <div className="mb-2 px-2 text-xs font-semibold uppercase text-(--color-muted)">{group.section}</div>
                  <div className="space-y-1">
                    {group.items.map((item, index) => (
                      <button
                        key={item.label}
                        className={`flex w-full items-center gap-2 rounded-md border-l-2 px-3 py-2 text-left text-sm hover:bg-white/8 ${
                          group.section === "Overview" && index === 0
                            ? "border-(--color-accent) bg-white/10 text-(--color-text)"
                            : "border-transparent text-(--color-muted)"
                        }`}
                      >
                        <item.icon size={17} />
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </nav>
          </aside>

          <section className="min-w-0 px-6 py-5">
            <header className="mb-5 flex items-center justify-between">
              <div>
                <div className="text-sm text-(--color-muted)">Overview / Risk</div>
                <h1 className="text-2xl font-semibold">Executive Risk Dashboard</h1>
              </div>
              <div className="flex items-center gap-2">
                <select
                  aria-label="Theme"
                  className="rounded-md border border-(--color-border) bg-(--color-surface) px-3 py-2 text-sm"
                  defaultValue="dark"
                  onChange={(event) => {
                    document.documentElement.dataset.theme = event.target.value;
                    localStorage.setItem("aegiscudo-theme", event.target.value);
                  }}
                >
                  <option value="dark">Dark</option>
                  <option value="dim">Dim</option>
                  <option value="light">Light</option>
                </select>
              </div>
            </header>

            <div ref={gridRef}>
              <ResponsiveGridLayout
                className="layout"
                width={gridWidth}
                breakpoints={{ lg: 1000, md: 760, sm: 480, xs: 0 }}
                cols={{ lg: 4, md: 2, sm: 1, xs: 1 }}
                rowHeight={116}
                dragConfig={{ enabled: true }}
                resizeConfig={{ enabled: true }}
                layouts={{
                  lg: metrics.map((metric, index) => ({ i: metric.label, x: index, y: 0, w: 1, h: 1 })),
                }}
              >
                {metrics.map((metric) => (
                  <motion.section
                    key={metric.label}
                    className="glow-panel p-4"
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ type: "spring", stiffness: 260, damping: 26 }}
                  >
                    <HelpTooltip content={metric.helper}>
                      <button className="mb-3 text-left text-sm text-(--color-muted)">{metric.label}</button>
                    </HelpTooltip>
                    <div className={`text-3xl font-semibold status-${metric.tone}`}>{metric.value}</div>
                  </motion.section>
                ))}
              </ResponsiveGridLayout>
            </div>

            <div className="mt-5 grid grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)] gap-5">
              <section className="glow-panel p-4">
                <div className="mb-4 flex items-center justify-between">
                  <h2 className="text-base font-semibold">Package Request Timeline</h2>
                  <span className="text-sm text-(--color-muted)">Last 8 hours</span>
                </div>
                <RequestTimelineChart />
              </section>

              <DecisionTable data={decisions} />
            </div>
          </section>
        </main>
      </TooltipProvider>
    </QueryClientProvider>
  );
}