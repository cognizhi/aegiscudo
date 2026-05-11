"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { KeyRound, Wifi, Trash2, AlertTriangle, CheckCircle2, Clock } from "lucide-react";
import { useState } from "react";

import {
  fetchCredentials,
  testCredentialConnection,
  deleteCredential,
  getDefaultTenantId,
} from "@/lib/control-plane";
import type { CredentialStatus, ConnectionTestResult } from "@aegiscudo/shared-types";

const CRED_TYPE_LABELS: Record<string, string> = {
  api_key: "API Key",
  basic_auth: "Basic Auth",
  bearer_token: "Bearer Token",
  aws_iam: "AWS IAM",
  gcp_workload_identity: "GCP Workload Identity",
  azure_managed_identity: "Azure Managed Identity",
};

function CredentialTypeIcon({ kind }: { kind: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <KeyRound size={12} className="text-(--color-muted)" />
      {CRED_TYPE_LABELS[kind] ?? kind}
    </span>
  );
}

function ConnectionStatusBadge({ result }: { result: ConnectionTestResult | null | "testing" }) {
  if (result === "testing") {
    return <span className="text-xs text-(--color-muted) animate-pulse">Testing…</span>;
  }
  if (!result) return null;
  return result.success ? (
    <span className="flex items-center gap-1 text-xs status-safe">
      <CheckCircle2 size={12} /> OK {result.latency_ms != null ? `(${result.latency_ms}ms)` : ""}
    </span>
  ) : (
    <span className="flex items-center gap-1 text-xs status-block" title={result.message}>
      <AlertTriangle size={12} /> Failed
    </span>
  );
}

interface CredentialRowProps {
  cred: CredentialStatus;
  onTest: (id: string) => void;
  onDelete: (id: string) => void;
  testResult: ConnectionTestResult | "testing" | null;
  deleting: boolean;
}

function CredentialRow({ cred, onTest, onDelete, testResult, deleting }: CredentialRowProps) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  return (
    <motion.tr
      layout
      className="border-b border-(--color-border) hover:bg-white/3 transition-colors"
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <td className="px-4 py-3 text-sm font-medium">{cred.name}</td>
      <td className="px-4 py-3">
        <CredentialTypeIcon kind={cred.credential_type} />
      </td>
      <td className="px-4 py-3">
        {cred.configured ? (
          <span className="flex items-center gap-1 text-xs status-safe">
            <CheckCircle2 size={12} /> Configured
          </span>
        ) : (
          <span className="flex items-center gap-1 text-xs text-(--color-muted)">
            <Clock size={12} /> Not configured
          </span>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-(--color-muted)">
        {new Date(cred.created_at).toLocaleDateString()}
      </td>
      <td className="px-4 py-3 text-xs text-(--color-muted)">
        {new Date(cred.updated_at).toLocaleDateString()}
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-3">
          <button
            aria-label={`Test connection for ${cred.name}`}
            className="flex items-center gap-1 rounded px-2 py-1 text-xs text-(--color-muted) hover:text-(--color-text) hover:bg-white/10 transition-colors disabled:opacity-40"
            disabled={testResult === "testing" || !cred.configured}
            onClick={() => onTest(cred.id)}
          >
            <Wifi size={12} />
            Test
          </button>
          <ConnectionStatusBadge result={testResult} />
        </div>
      </td>
      <td className="px-4 py-3">
        {confirmDelete ? (
          <div className="flex items-center gap-2">
            <span className="text-xs text-(--color-muted)">Delete?</span>
            <button
              className="rounded px-2 py-1 text-xs status-block bg-red-900/30 hover:bg-red-900/60 transition-colors disabled:opacity-50"
              disabled={deleting}
              onClick={() => onDelete(cred.id)}
            >
              {deleting ? "…" : "Yes"}
            </button>
            <button
              className="rounded px-2 py-1 text-xs text-(--color-muted) hover:text-(--color-text) transition-colors"
              onClick={() => setConfirmDelete(false)}
            >
              No
            </button>
          </div>
        ) : (
          <button
            aria-label={`Delete ${cred.name}`}
            className="rounded p-1 text-(--color-muted) hover:text-red-400 hover:bg-red-900/20 transition-colors disabled:opacity-30"
            disabled={deleting}
            onClick={() => setConfirmDelete(true)}
          >
            <Trash2 size={14} />
          </button>
        )}
      </td>
    </motion.tr>
  );
}

export function IntegrationsPanel() {
  const tenantId = getDefaultTenantId();
  const queryClient = useQueryClient();

  const [testResults, setTestResults] = useState<
    Record<string, ConnectionTestResult | "testing" | null>
  >({});

  const { data: credentials = [], isLoading, error } = useQuery({
    queryKey: ["credentials", tenantId],
    queryFn: () => fetchCredentials(tenantId),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteCredential(tenantId, id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["credentials", tenantId] });
    },
  });

  async function handleTest(credentialId: string) {
    setTestResults((prev) => ({ ...prev, [credentialId]: "testing" }));
    try {
      const result = await testCredentialConnection(tenantId, credentialId);
      setTestResults((prev) => ({ ...prev, [credentialId]: result }));
    } catch {
      setTestResults((prev) => ({
        ...prev,
        [credentialId]: { success: false, message: "Connection test request failed" },
      }));
    }
  }

  return (
    <section className="glow-panel">
      <header className="flex items-center gap-2 border-b border-(--color-border) px-4 py-3 text-sm font-semibold">
        <KeyRound size={16} className="text-(--color-accent)" />
        Integrations &amp; Credentials
      </header>

      <div className="p-4">
        {isLoading && (
          <div className="py-8 text-center text-sm text-(--color-muted)">Loading credentials…</div>
        )}
        {error && (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load credentials"}
          </div>
        )}
        {!isLoading && !error && credentials.length === 0 && (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No credentials configured. Add credentials to connect your upstream registries and AI providers.
          </div>
        )}
        {credentials.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-(--color-border)">
                  {["Name", "Type", "Status", "Created", "Updated", "Actions", ""].map((h) => (
                    <th key={h} className="px-4 py-2 text-xs font-semibold uppercase text-(--color-muted)">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {credentials.map((cred) => (
                  <CredentialRow
                    key={cred.id}
                    cred={cred}
                    onTest={handleTest}
                    onDelete={(id) => deleteMutation.mutate(id)}
                    testResult={testResults[cred.id] ?? null}
                    deleting={deleteMutation.isPending && deleteMutation.variables === cred.id}
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
