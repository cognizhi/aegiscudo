"use client";

import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Bot, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";

import { fetchAiProviders, getDefaultTenantId } from "@/lib/control-plane";
import type { AiProviderConfig } from "@aegiscudo/shared-types";

const PROVIDER_LABELS: Record<string, string> = {
  openrouter: "OpenRouter",
  openai: "OpenAI",
  anthropic: "Anthropic",
  google_gemini: "Google Gemini",
  google_vertex: "Google Vertex AI",
  ollama: "Ollama",
  lm_studio: "LM Studio",
  vllm: "vLLM",
  generic_openai: "Generic OpenAI-compatible",
};

interface ProviderRowProps {
  provider: AiProviderConfig;
}

function ProviderRow({ provider }: ProviderRowProps) {
  return (
    <motion.tr
      layout
      className="border-b border-(--color-border) hover:bg-white/3 transition-colors"
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <td className="px-4 py-3 text-sm font-medium">
        <div className="flex items-center gap-2">
          {provider.display_name}
          {provider.active && (
            <span className="rounded bg-green-900/30 px-1.5 py-0.5 text-[10px] font-medium status-safe">
              Active
            </span>
          )}
        </div>
      </td>
      <td className="px-4 py-3 text-xs">
        {PROVIDER_LABELS[provider.provider_type] ?? provider.provider_type}
      </td>
      <td className="px-4 py-3 text-xs font-mono text-(--color-muted)">{provider.model_id}</td>
      <td className="px-4 py-3">
        <span
          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${
            provider.is_local
              ? "bg-blue-900/30 text-blue-300"
              : "bg-orange-900/20 text-orange-300"
          }`}
        >
          {provider.is_local ? "Local" : "Cloud"}
        </span>
      </td>
      <td className="px-4 py-3">
        {provider.active ? (
          <CheckCircle2 size={15} className="status-safe" />
        ) : (
          <XCircle size={15} className="text-(--color-muted)" />
        )}
      </td>
      <td className="px-4 py-3 text-xs text-(--color-muted)">
        {provider.base_url ? (
          <span className="font-mono truncate max-w-40 block" title={provider.base_url}>
            {provider.base_url}
          </span>
        ) : (
          <span className="italic">default endpoint</span>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-(--color-muted)">
        {new Date(provider.updated_at).toLocaleDateString()}
      </td>
    </motion.tr>
  );
}

export function AiProvidersPanel() {
  const tenantId = getDefaultTenantId();

  const { data: providers = [], isLoading, error } = useQuery({
    queryKey: ["ai-providers", tenantId],
    queryFn: () => fetchAiProviders(tenantId),
  });

  return (
    <section className="glow-panel">
      <header className="flex items-center gap-2 border-b border-(--color-border) px-4 py-3 text-sm font-semibold">
        <Bot size={16} className="text-(--color-accent)" />
        AI Providers
      </header>

      <div className="p-4">
        {isLoading && (
          <div className="py-8 text-center text-sm text-(--color-muted)">Loading AI providers…</div>
        )}
        {error && (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load AI providers"}
          </div>
        )}
        {!isLoading && !error && providers.length === 0 && (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No AI provider configured. Add a provider configuration to enable AI explanations.
          </div>
        )}
        {providers.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-(--color-border)">
                  {["Display Name", "Provider", "Model", "Data Boundary", "Active", "Base URL", "Updated"].map((h) => (
                    <th key={h} className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {providers.map((provider) => (
                  <ProviderRow key={provider.id} provider={provider} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
