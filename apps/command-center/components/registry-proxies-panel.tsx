"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Globe, Plus, Trash2, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { useState } from "react";

import {
  fetchRegistryConfigs,
  deleteRegistryConfig,
  getDefaultTenantId,
} from "@/lib/control-plane";
import type { RegistryConfig } from "@aegiscudo/shared-types";

const ADAPTER_LABELS: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "Cargo",
  maven: "Maven",
  "docker-oci": "Docker / OCI",
  "generic-http": "Generic HTTP",
};

const MODE_TONE: Record<string, string> = {
  shadow: "warn",
  warn: "warn",
  enforce: "block",
};

function AdapterBadge({ adapter }: { adapter: string }) {
  const phase1 = adapter === "npm" || adapter === "pypi";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${
        phase1 ? "bg-white/10 text-(--color-text)" : "bg-white/5 text-(--color-muted)"
      }`}
    >
      {ADAPTER_LABELS[adapter] ?? adapter}
      {!phase1 && (
        <span className="ml-1 rounded bg-white/10 px-1 text-[10px]">coming soon</span>
      )}
    </span>
  );
}

function ModeBadge({ mode }: { mode: string }) {
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium status-${MODE_TONE[mode] ?? "neutral"}`}>
      {mode}
    </span>
  );
}

function EnabledToggle({ enabled }: { enabled: boolean }) {
  return enabled ? (
    <CheckCircle2 size={16} className="status-safe" />
  ) : (
    <XCircle size={16} className="text-(--color-muted)" />
  );
}

interface RegistryProxyRowProps {
  config: RegistryConfig;
  onDelete: (id: string) => void;
  deleting: boolean;
}

function RegistryProxyRow({ config, onDelete, deleting }: RegistryProxyRowProps) {
  const [confirming, setConfirming] = useState(false);

  return (
    <motion.tr
      layout
      className="border-b border-(--color-border) hover:bg-white/3 transition-colors"
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <td className="px-4 py-3 text-sm font-medium">{config.name}</td>
      <td className="px-4 py-3">
        <AdapterBadge adapter={config.adapter} />
      </td>
      <td className="px-4 py-3 text-xs text-(--color-muted) font-mono max-w-48 truncate" title={config.upstream_url}>
        {config.upstream_url}
      </td>
      <td className="px-4 py-3 text-xs font-mono text-(--color-muted)">{config.mount_path}</td>
      <td className="px-4 py-3">
        <ModeBadge mode={config.mode} />
      </td>
      <td className="px-4 py-3">
        <EnabledToggle enabled={config.enabled} />
      </td>
      <td className="px-4 py-3 text-xs text-(--color-muted)">
        {new Date(config.updated_at).toLocaleDateString()}
      </td>
      <td className="px-4 py-3">
        {confirming ? (
          <div className="flex items-center gap-2">
            <span className="text-xs text-(--color-muted)">Delete?</span>
            <button
              className="rounded px-2 py-1 text-xs status-block bg-red-900/30 hover:bg-red-900/60 transition-colors disabled:opacity-50"
              disabled={deleting}
              onClick={() => onDelete(config.id)}
            >
              {deleting ? "…" : "Yes"}
            </button>
            <button
              className="rounded px-2 py-1 text-xs text-(--color-muted) hover:text-(--color-text) transition-colors"
              onClick={() => setConfirming(false)}
            >
              No
            </button>
          </div>
        ) : (
          <button
            aria-label={`Delete ${config.name}`}
            className="rounded p-1 text-(--color-muted) hover:text-red-400 hover:bg-red-900/20 transition-colors disabled:opacity-30"
            disabled={deleting}
            onClick={() => setConfirming(true)}
          >
            <Trash2 size={14} />
          </button>
        )}
      </td>
    </motion.tr>
  );
}

export function RegistryProxiesPanel() {
  const tenantId = getDefaultTenantId();
  const queryClient = useQueryClient();

  const { data: configs = [], isLoading, error } = useQuery({
    queryKey: ["registry-configs", tenantId],
    queryFn: () => fetchRegistryConfigs(tenantId),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteRegistryConfig(tenantId, id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["registry-configs", tenantId] });
    },
  });

  return (
    <section className="glow-panel">
      <header className="flex items-center justify-between border-b border-(--color-border) px-4 py-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Globe size={16} className="text-(--color-accent)" />
          Registry Proxies
        </div>
        <button
          className="flex items-center gap-1.5 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10 transition-colors"
          aria-label="Add registry proxy"
          title="Adding new registry proxies is available in the admin settings"
        >
          <Plus size={13} />
          Add Proxy
        </button>
      </header>

      <div className="p-4">
        {isLoading && (
          <div className="py-8 text-center text-sm text-(--color-muted)">Loading registry configurations…</div>
        )}
        {error && (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load registry configs"}
          </div>
        )}
        {!isLoading && !error && configs.length === 0 && (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No registry proxies configured. Add one to start inspecting packages.
          </div>
        )}
        {configs.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-(--color-border)">
                  {["Name", "Adapter", "Upstream URL", "Mount Path", "Mode", "Enabled", "Updated", ""].map((h) => (
                    <th key={h} className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {configs.map((config) => (
                  <RegistryProxyRow
                    key={config.id}
                    config={config}
                    onDelete={(id) => deleteMutation.mutate(id)}
                    deleting={deleteMutation.isPending && deleteMutation.variables === config.id}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
