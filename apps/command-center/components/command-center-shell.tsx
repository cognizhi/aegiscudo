"use client";

import type { DashboardMetrics } from "@aegiscudo/shared-types";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Activity, Bot, Boxes, Cpu, Gauge, KeyRound, LayoutDashboard, ScrollText, Settings, ShieldCheck, Siren, UserCircle } from "lucide-react";
import dynamic from "next/dynamic";
import { useEffect, useMemo, useRef, useState } from "react";
import { ResponsiveGridLayout } from "react-grid-layout";

import {
  DEFAULT_PERSONA_ID,
  MOCK_PERSONAS,
  type NavSection,
  type PersonaId,
  getPersona,
  loadPersistedPersonaId,
  persistPersonaId,
} from "@/lib/mock-personas";
import { fetchDashboardMetrics, getDefaultTenantId } from "@/lib/control-plane";

import { AiProvidersPanel } from "./ai-providers-panel";
import { AuditLogPanel } from "./audit-log-panel";
import { CommandPaletteTrigger } from "./command-palette";
import { DecisionTable } from "./decision-table";
import { IntegrationsPanel } from "./integrations-panel";
import { LlmUsagePanel } from "./llm-usage-panel";
import { OpenVexDocumentsPanel } from "./openvex-documents-panel";
import { OverrideQueue } from "./override-queue";
import { PolicySimulatorPanel } from "./policy-simulator-panel";
import { DepsDdevPackagesPanel } from "./deps-dev-packages-panel";
import { GithubActionsScanResultsPanel } from "./github-actions-scan-results-panel";
import { IocRecordsPanel } from "./ioc-records-panel";
import { ScorecardThresholdsPanel } from "./scorecard-thresholds-panel";
import { RegistryProxiesPanel } from "./registry-proxies-panel";
import { SbomExportsPanel } from "./sbom-exports-panel";
import { HelpTooltip, TooltipProvider } from "./ui/tooltip";

const RequestTimelineChart = dynamic(
  () => import("./request-timeline-chart").then((module) => module.RequestTimelineChart),
  {
    ssr: false,
    loading: () => <div className="h-77.5 rounded-md bg-white/5" aria-label="Loading chart" />,
  },
);

type NavKey =
  | "overview-risk"
  | "analysis-evidence"
  | "analysis-sandbox"
  | "policy-simulator"
  | "feeds-registry"
  | "admin-integrations"
  | "admin-ai-providers"
  | "admin-llm-usage"
  | "admin-audit-log"
  | "admin-settings";

type NavItem = {
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  navKey: NavKey;
  visibleToPersonas?: PersonaId[];
};

const navigation: {
  section: string;
  navSection: NavSection;
  items: NavItem[];
}[] = [
  {
    section: "Overview",
    navSection: "overview",
    items: [{ label: "Risk", icon: LayoutDashboard, navKey: "overview-risk" }],
  },
  {
    section: "Analysis",
    navSection: "analysis",
    items: [
      { label: "Evidence", icon: Activity, navKey: "analysis-evidence" },
      { label: "Sandbox", icon: Siren, navKey: "analysis-sandbox" },
    ],
  },
  {
    section: "Policy",
    navSection: "policy",
    items: [{ label: "Simulator", icon: Gauge, navKey: "policy-simulator" }],
  },
  {
    section: "Feeds",
    navSection: "feeds",
    items: [{ label: "Registry", icon: Boxes, navKey: "feeds-registry" }],
  },
  {
    section: "Admin",
    navSection: "admin",
    items: [
      { label: "Integrations", icon: KeyRound, navKey: "admin-integrations" },
      { label: "AI Providers", icon: Bot, navKey: "admin-ai-providers" },
      { label: "LLM Usage", icon: Cpu, navKey: "admin-llm-usage", visibleToPersonas: ["platform-admin"] },
      { label: "Audit Log", icon: ScrollText, navKey: "admin-audit-log" },
      { label: "Settings", icon: Settings, navKey: "admin-settings" },
    ],
  },
];

const NAV_TITLES: Record<NavKey, { breadcrumb: string; title: string }> = {
  "overview-risk": { breadcrumb: "Overview / Risk", title: "Executive Risk Dashboard" },
  "analysis-evidence": { breadcrumb: "Analysis / Evidence", title: "Artifact Evidence" },
  "analysis-sandbox": { breadcrumb: "Analysis / Sandbox", title: "Sandbox Results" },
  "policy-simulator": { breadcrumb: "Policy / Simulator", title: "Policy Simulator" },
  "feeds-registry": { breadcrumb: "Feeds / Registry", title: "Registry Proxies" },
  "admin-integrations": { breadcrumb: "Admin / Integrations", title: "Integrations & Credentials" },
  "admin-ai-providers": { breadcrumb: "Admin / AI Providers", title: "AI Providers" },
  "admin-llm-usage": { breadcrumb: "Admin / LLM Usage", title: "LLM Usage" },
  "admin-audit-log": { breadcrumb: "Admin / Audit Log", title: "Audit Log" },
  "admin-settings": { breadcrumb: "Admin / Settings", title: "Settings" },
};

function PlaceholderPanel({ label }: { label: string }) {
  return (
    <section className="glow-panel p-8 text-center">
      <p className="text-(--color-muted) text-sm">{label} — coming in a future phase.</p>
    </section>
  );
}

type DashboardMetricCard = {
  label: string;
  value: string;
  tone: "critical" | "warning" | "pending" | "safe" | "info";
  helper: string;
};

const fallbackDashboardMetrics: DashboardMetrics = {
  blocked_packages: 0,
  quarantine_queue_depth: 0,
  active_overrides: 0,
  feed_freshness: "missing",
  feed_snapshot_age_seconds: null,
};

function buildDashboardMetricCards(metrics: DashboardMetrics): DashboardMetricCard[] {
  const feedTone =
    metrics.feed_freshness === "fresh"
      ? "safe"
      : metrics.feed_freshness === "stale"
        ? "warning"
        : "pending";
  const feedFreshnessLabel = metrics.feed_freshness.replace(/^./, (value) => value.toUpperCase());

  return [
    {
      label: "Blocked",
      value: String(metrics.blocked_packages),
      tone: "critical",
      helper: "Packages stopped by policy based on persisted completed analysis summaries.",
    },
    {
      label: "Quarantine",
      value: String(metrics.quarantine_queue_depth),
      tone: "warning",
      helper: "Artifacts currently requiring manual review or awaiting quarantine resolution.",
    },
    {
      label: "Overrides",
      value: String(metrics.active_overrides),
      tone: "pending",
      helper: "Active pending or approved time-bound exceptions that have not expired.",
    },
    {
      label: "Feed State",
      value: feedFreshnessLabel,
      tone: feedTone,
      helper:
        metrics.feed_snapshot_age_seconds === null
          ? "No successful feed snapshots are recorded yet for this tenant."
          : "Worst-case age across the latest successful snapshot for each configured feed.",
    },
  ];
}

function DashboardView({ gridWidth, gridRef }: { gridWidth: number; gridRef: React.RefObject<HTMLDivElement | null> }) {
  const tenantId = getDefaultTenantId();
  const dashboardMetricsQuery = useQuery({
    queryKey: ["dashboard-metrics", tenantId],
    queryFn: () => fetchDashboardMetrics(tenantId),
    initialData: fallbackDashboardMetrics,
    staleTime: 30_000,
    retry: false,
  });
  const metricCards = buildDashboardMetricCards(dashboardMetricsQuery.data ?? fallbackDashboardMetrics);

  return (
    <>
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
            lg: metricCards.map((metric, index) => ({ i: metric.label, x: index, y: 0, w: 1, h: 1 })),
          }}
        >
          {metricCards.map((metric) => (
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
      {dashboardMetricsQuery.error instanceof Error ? (
        <div className="mt-3 text-sm text-(--color-warning)">{dashboardMetricsQuery.error.message}</div>
      ) : null}

      <div className="mt-5 grid grid-cols-[minmax(0,1.1fr)_minmax(360px,0.9fr)] gap-5">
        <section className="glow-panel p-4">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold">Package Request Timeline</h2>
            <span className="text-sm text-(--color-muted)">Latest 8 hours</span>
          </div>
          <RequestTimelineChart />
        </section>

        <DecisionTable />
      </div>

      <div className="mt-5">
        <OverrideQueue />
      </div>
    </>
  );
}

type CommandCenterShellProps = {
  appVersion: string;
};

export function CommandCenterShell({ appVersion }: CommandCenterShellProps) {
  const queryClient = useMemo(() => new QueryClient(), []);
  const gridRef = useRef<HTMLDivElement>(null);
  const [gridWidth, setGridWidth] = useState(1000);
  const [activeNav, setActiveNav] = useState<NavKey>("overview-risk");
  const [personaId, setPersonaId] = useState<PersonaId>(DEFAULT_PERSONA_ID);
  const [isAboutOpen, setIsAboutOpen] = useState(false);

  useEffect(() => {
    setPersonaId(loadPersistedPersonaId());
  }, []);

  useEffect(() => {
    queryClient.clear();
  }, [personaId, queryClient]);

  const persona = getPersona(personaId);

  const visibleNavGroups = useMemo(
    () =>
      navigation
        .filter((group) => persona.allowedSections.includes(group.navSection))
        .map((group) => ({
          ...group,
          items: group.items.filter(
            (item) => !item.visibleToPersonas || item.visibleToPersonas.includes(persona.id),
          ),
        }))
        .filter((group) => group.items.length > 0),
    [persona.id, persona.allowedSections],
  );
  const visibleNavKeys = useMemo(
    () => visibleNavGroups.flatMap((group) => group.items.map((item) => item.navKey)),
    [visibleNavGroups],
  );
  const fallbackNav = visibleNavKeys[0] ?? "overview-risk";

  useEffect(() => {
    if (!visibleNavKeys.includes(activeNav)) {
      setActiveNav(fallbackNav);
    }
  }, [activeNav, fallbackNav, visibleNavKeys]);

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

  useEffect(() => {
    if (!isAboutOpen) {
      return undefined;
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsAboutOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isAboutOpen]);

  const { breadcrumb, title } = NAV_TITLES[activeNav];

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <main className="grid min-h-screen grid-cols-[240px_1fr] bg-(--color-bg)">
          <aside className="flex min-h-screen flex-col border-r border-(--color-border) bg-(--color-surface) px-3 py-4">
            <div className="mb-6 flex items-center gap-2 px-2 text-(--color-accent)">
              <ShieldCheck size={24} />
              <span className="text-lg font-semibold">Aegiscudo</span>
            </div>
            <nav className="flex-1 space-y-5">
              {visibleNavGroups.map((group) => (
                <div key={group.section}>
                  <div className="mb-2 px-2 text-xs font-semibold uppercase text-(--color-muted)">{group.section}</div>
                  <div className="space-y-1">
                    {group.items.map((item) => {
                      const isActive = activeNav === item.navKey;
                      return (
                        <button
                          key={item.label}
                          className={`flex w-full items-center gap-2 rounded-md border-l-2 px-3 py-2 text-left text-sm hover:bg-white/8 ${
                            isActive
                              ? "border-(--color-accent) bg-white/10 text-(--color-text)"
                              : "border-transparent text-(--color-muted)"
                          }`}
                          onClick={() => setActiveNav(item.navKey)}
                        >
                          <item.icon size={17} />
                          {item.label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </nav>

            <div className="mt-6 rounded-xl border border-(--color-border) bg-(--color-surface-elevated) px-3 py-3 shadow-[var(--glow-strength)]">
              <div className="text-[0.7rem] font-semibold uppercase tracking-[0.18em] text-(--color-muted)">
                Command Center
              </div>
              <div className="mt-2 flex items-end justify-between gap-3">
                <div>
                  <div className="text-xs text-(--color-muted)">Version</div>
                  <div className="font-mono text-sm text-(--color-text)">v{appVersion}</div>
                </div>
                <button
                  type="button"
                  className="rounded-md border border-(--color-border) px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.16em] text-(--color-accent) hover:bg-white/6"
                  onClick={() => setIsAboutOpen(true)}
                >
                  About
                </button>
              </div>
            </div>
          </aside>

          <section className="min-w-0 px-6 py-5">
            <header className="mb-5 flex items-center justify-between">
              <div>
                <nav aria-label="Breadcrumb" data-testid="breadcrumb">
                  <ol className="flex items-center gap-1 text-sm text-(--color-muted)">
                    {breadcrumb.split(" / ").map((segment, i, arr) => (
                      <li key={segment} className="flex items-center gap-1">
                        {i > 0 && <span aria-hidden="true">/</span>}
                        <span aria-current={i === arr.length - 1 ? "page" : undefined}>{segment}</span>
                      </li>
                    ))}
                  </ol>
                </nav>
                <h1 className="text-2xl font-semibold">{title}</h1>
              </div>
              <div className="flex items-center gap-2">
                <CommandPaletteTrigger />
                <div className="flex items-center gap-1 rounded-md border border-(--color-border) bg-(--color-surface) px-2 py-1 text-sm">
                  <UserCircle size={15} className="text-(--color-muted)" />
                  <select
                    aria-label="Persona"
                    className="bg-transparent text-(--color-text) focus:outline-none"
                    value={personaId}
                    onChange={(event) => {
                      const next = event.target.value as PersonaId;
                      setPersonaId(next);
                      persistPersonaId(next);
                    }}
                  >
                    {MOCK_PERSONAS.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.displayName}
                      </option>
                    ))}
                  </select>
                </div>
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

            {activeNav === "overview-risk" && (
              <DashboardView gridWidth={gridWidth} gridRef={gridRef} />
            )}
            {activeNav === "policy-simulator" && <PolicySimulatorPanel />}
            {activeNav === "feeds-registry" && <RegistryProxiesPanel />}
            {activeNav === "admin-integrations" && <IntegrationsPanel />}
            {activeNav === "admin-ai-providers" && <AiProvidersPanel />}
            {activeNav === "admin-llm-usage" && <LlmUsagePanel />}
            {activeNav === "admin-audit-log" && <AuditLogPanel />}
            {activeNav === "analysis-evidence" && (
              <div className="space-y-5">
                <SbomExportsPanel />
                <OpenVexDocumentsPanel />
                <ScorecardThresholdsPanel />
                <DepsDdevPackagesPanel />
                <IocRecordsPanel />
                <GithubActionsScanResultsPanel />
              </div>
            )}
            {(activeNav === "analysis-sandbox" || activeNav === "admin-settings") && (
              <PlaceholderPanel label={NAV_TITLES[activeNav].title} />
            )}
          </section>
        </main>

        {isAboutOpen ? (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" role="presentation">
            <section
              aria-labelledby="about-panel-title"
              aria-modal="true"
              className="glow-panel w-full max-w-md border border-(--color-border) bg-(--color-surface-elevated) p-6"
              role="dialog"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-[0.7rem] font-semibold uppercase tracking-[0.18em] text-(--color-accent)">
                    About
                  </div>
                  <h2 id="about-panel-title" className="mt-2 text-xl font-semibold">
                    Aegiscudo Command Center
                  </h2>
                </div>
                <button
                  aria-label="Close About panel"
                  className="rounded-md border border-(--color-border) px-3 py-1.5 text-sm text-(--color-muted) hover:bg-white/6"
                  onClick={() => setIsAboutOpen(false)}
                  type="button"
                >
                  Close
                </button>
              </div>

              <p className="mt-4 text-sm leading-6 text-(--color-muted)">
                Supply chain security operations console for request-time policy, investigation, and response workflows.
              </p>

              <div className="mt-5 grid gap-3">
                <div className="rounded-lg border border-(--color-border) bg-(--color-surface) px-4 py-3">
                  <div className="text-xs font-semibold uppercase tracking-[0.16em] text-(--color-muted)">Version</div>
                  <div className="mt-2 font-mono text-base text-(--color-text)">v{appVersion}</div>
                </div>
                <div className="rounded-lg border border-(--color-border) bg-(--color-surface) px-4 py-3 text-sm text-(--color-muted)">
                  Injected from <span className="font-mono text-(--color-text)">NEXT_PUBLIC_APP_VERSION</span> at build time.
                </div>
              </div>
            </section>
          </div>
        ) : null}
      </TooltipProvider>
    </QueryClientProvider>
  );
}