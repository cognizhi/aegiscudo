"use client";

import type { OpenVexExpiryPolicy } from "@aegiscudo/shared-types";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import {
  fetchTenantOpenVexDocument,
  fetchTenantOpenVexDocuments,
  getDefaultTenantId,
} from "@/lib/control-plane";

type OpenVexStatement = {
  vulnerabilityName: string;
  status: string;
  products: string[];
  justification: string | null;
  actionStatement: string | null;
  impactStatement: string | null;
  timestamp: string | null;
};

function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString();
}

function titleCase(value: string): string {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(" ");
}

function formatExpiryPolicy(policy: OpenVexExpiryPolicy): string {
  if (policy.mode === "never") {
    return "No expiry";
  }
  if (!policy.expires_at) {
    return "Expiry pending";
  }
  const expiry = new Date(policy.expires_at);
  if (Number.isNaN(expiry.getTime())) {
    return "Expiry pending";
  }
  return expiry.getTime() <= Date.now()
    ? `Expired ${expiry.toLocaleString()}`
    : `Expires ${expiry.toLocaleString()}`;
}

function statusClassName(status: string): string {
  if (status === "fixed" || status === "not_affected") {
    return "status-safe";
  }
  if (status === "affected") {
    return "status-block";
  }
  return "status-warning";
}

function countStatements(statements: OpenVexStatement[], statuses: string[]): number {
  return statements.filter((statement) => statuses.includes(statement.status)).length;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function asRecordArray(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value
        .map((entry) => asRecord(entry))
        .filter((entry) => Object.keys(entry).length > 0)
    : [];
}

function extractStatements(document: Record<string, unknown>): OpenVexStatement[] {
  const rawStatements = asRecordArray(document.statements);
  return rawStatements.map((statement) => {
    const vulnerability = asRecord(statement.vulnerability);
    const products = asRecordArray(statement.products)
      .map((product) => asString(product["@id"]))
      .filter((value): value is string => value !== null);

    return {
      vulnerabilityName: asString(vulnerability.name) ?? "Unknown vulnerability",
      status: asString(statement.status) ?? "under_investigation",
      products,
      justification: asString(statement.justification),
      actionStatement: asString(statement.action_statement),
      impactStatement: asString(statement.impact_statement),
      timestamp: asString(statement.timestamp),
    } satisfies OpenVexStatement;
  });
}

function SummaryValue({ label, value, testId }: { label: string; value: string; testId?: string }) {
  return (
    <div className="rounded-lg border border-(--color-border) bg-white/5 px-3 py-2" data-testid={testId}>
      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">{label}</div>
      <div className="mt-1 text-xl font-semibold" data-testid={testId ? `${testId}-value` : undefined}>
        {value}
      </div>
    </div>
  );
}

function MetadataItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-(--color-border) bg-white/4 px-3 py-2">
      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">{label}</div>
      <div className="mt-1 text-sm text-(--color-text)">{value}</div>
    </div>
  );
}

export function OpenVexDocumentsPanel() {
  const tenantId = getDefaultTenantId();
  const [selectedDocumentId, setSelectedDocumentId] = useState<string | null>(null);
  const {
    data: documents = [],
    isLoading,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["tenant-openvex-documents", tenantId],
    queryFn: () => fetchTenantOpenVexDocuments(tenantId),
    staleTime: 30_000,
  });

  useEffect(() => {
    if (documents.length === 0) {
      setSelectedDocumentId(null);
      return;
    }
    if (!selectedDocumentId || !documents.some((document) => document.id === selectedDocumentId)) {
      setSelectedDocumentId(documents[0]?.id ?? null);
    }
  }, [documents, selectedDocumentId]);

  const detailQuery = useQuery({
    queryKey: ["tenant-openvex-document", tenantId, selectedDocumentId],
    queryFn: () => fetchTenantOpenVexDocument(tenantId, selectedDocumentId ?? ""),
    enabled: selectedDocumentId !== null,
    staleTime: 30_000,
  });

  const selectedSummary =
    documents.find((document) => document.id === selectedDocumentId) ?? documents[0] ?? null;
  const selectedDocument = detailQuery.data;
  const statements = extractStatements(asRecord(selectedDocument?.document));

  return (
    <section className="glow-panel overflow-hidden" data-testid="openvex-documents-panel">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-(--color-border) px-4 py-3">
        <div>
          <div className="flex items-center gap-2 text-sm font-semibold">
            <ShieldCheck size={16} className="text-(--color-accent)" />
            OpenVEX Import State
          </div>
          <p className="mt-1 text-sm text-(--color-muted)">
            Imported tenant-scoped OpenVEX documents and their statement history for the active tenant.
          </p>
        </div>
        <button
          className="inline-flex items-center gap-1 rounded-md border border-(--color-border) bg-white/5 px-3 py-1.5 text-xs font-medium text-(--color-text) hover:bg-white/10 disabled:opacity-50"
          disabled={isFetching}
          onClick={() => {
            void refetch();
          }}
          type="button"
        >
          <RefreshCw size={13} className={isFetching ? "animate-spin" : ""} />
          Refresh
        </button>
      </header>

      <div className="border-b border-(--color-border) px-4 py-3 text-xs text-(--color-muted)">
        Showing imported OpenVEX documents for the active tenant. Request-time suppression is still pending
        component-level vulnerability correlation, so this panel reflects import state rather than enforced
        suppression outcomes.
      </div>

      <div className="p-4">
        {isLoading ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">Loading OpenVEX documents…</div>
        ) : null}

        {error ? (
          <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
            <AlertTriangle size={14} />
            {error instanceof Error ? error.message : "Failed to load OpenVEX documents"}
          </div>
        ) : null}

        {!isLoading && !error && documents.length === 0 ? (
          <div className="py-8 text-center text-sm text-(--color-muted)">
            No tenant-scoped OpenVEX documents have been imported yet.
          </div>
        ) : null}

        {documents.length > 0 ? (
          <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.85fr)_minmax(0,1.15fr)]">
            <div className="rounded-lg border border-(--color-border) bg-black/10">
              <div className="border-b border-(--color-border) px-4 py-3 text-xs uppercase tracking-[0.18em] text-(--color-muted)">
                Recent imports
              </div>
              <div className="divide-y divide-(--color-border)">
                {documents.map((document) => {
                  const isSelected = document.id === selectedSummary?.id;
                  return (
                    <button
                      key={document.id}
                      className={`block w-full px-4 py-3 text-left transition ${
                        isSelected ? "bg-white/8" : "hover:bg-white/4"
                      }`}
                      onClick={() => setSelectedDocumentId(document.id)}
                      type="button"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-medium text-(--color-text)">{document.source}</div>
                          <div className="mt-1 text-xs text-(--color-muted)">{document.document_id}</div>
                        </div>
                        <div className="text-right text-xs text-(--color-muted)">
                          <div>{document.statement_count} statements</div>
                          <div>{formatExpiryPolicy(document.expiry_policy)}</div>
                        </div>
                      </div>
                      <div className="mt-2 text-xs text-(--color-muted)">
                        {document.author} · imported {formatTimestamp(document.imported_at)}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="rounded-lg border border-(--color-border) bg-black/10 p-4">
              {detailQuery.isLoading ? (
                <div className="py-8 text-center text-sm text-(--color-muted)">Loading OpenVEX detail…</div>
              ) : null}

              {detailQuery.error ? (
                <div className="flex items-center gap-2 rounded-md border border-red-900/30 bg-red-900/10 px-4 py-3 text-sm status-block">
                  <AlertTriangle size={14} />
                  {detailQuery.error instanceof Error
                    ? detailQuery.error.message
                    : "Failed to load OpenVEX detail"}
                </div>
              ) : null}

              {!detailQuery.isLoading && !detailQuery.error && selectedDocument ? (
                <>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="text-xs uppercase tracking-[0.18em] text-(--color-muted)">Selected document</div>
                      <h3 className="mt-1 text-base font-semibold text-(--color-text)">{selectedDocument.source}</h3>
                      <div className="mt-1 break-all text-xs text-(--color-muted)">{selectedDocument.document_id}</div>
                    </div>
                    <div className="text-right text-xs text-(--color-muted)">
                      <div>{formatTimestamp(selectedDocument.imported_at)}</div>
                      <div>{formatExpiryPolicy(selectedDocument.expiry_policy)}</div>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-3 md:grid-cols-4">
                    <SummaryValue
                      label="Statements"
                      value={String(statements.length)}
                      testId="openvex-summary-statements"
                    />
                    <SummaryValue
                      label="Fixed or Not Affected"
                      value={String(countStatements(statements, ["fixed", "not_affected"]))}
                      testId="openvex-summary-suppressed"
                    />
                    <SummaryValue
                      label="Under Investigation"
                      value={String(countStatements(statements, ["under_investigation"]))}
                      testId="openvex-summary-under-investigation"
                    />
                    <SummaryValue
                      label="Affected"
                      value={String(countStatements(statements, ["affected"]))}
                      testId="openvex-summary-affected"
                    />
                  </div>

                  <div
                    className="mt-4 rounded-lg border border-(--color-warning)/40 bg-(--color-warning)/10 px-4 py-3 text-sm text-(--color-text)"
                    data-testid="openvex-suppression-state"
                  >
                    Request-time suppression is still pending component-level vulnerability correlation. Imported
                    OpenVEX statements are visible here, but these documents are not yet suppressing vulnerability
                    matches in live policy decisions.
                  </div>

                  <div className="mt-4 grid gap-3 md:grid-cols-2">
                    <MetadataItem label="Author" value={selectedDocument.author} />
                    <MetadataItem label="Context" value={selectedDocument.context} />
                    <MetadataItem label="Version" value={String(selectedDocument.version)} />
                    <MetadataItem label="Document timestamp" value={formatTimestamp(selectedDocument.document_timestamp)} />
                    <MetadataItem label="Digest" value={selectedDocument.document_digest} />
                    <MetadataItem label="Statement count" value={String(selectedDocument.statement_count)} />
                  </div>

                  <div className="mt-4 space-y-3">
                    {statements.map((statement, index) => (
                      <div
                        key={`${selectedDocument.id}-statement-${index + 1}`}
                        className="rounded-lg border border-(--color-border) p-3"
                        data-testid={`openvex-statement-${index + 1}`}
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div>
                            <div className="text-sm font-medium text-(--color-text)">{statement.vulnerabilityName}</div>
                            <div className="mt-1 text-xs text-(--color-muted)">
                              {statement.products.length ? statement.products.join(" · ") : "No product IDs recorded"}
                            </div>
                          </div>
                          <div className="text-right">
                            <div className={`text-xs font-medium ${statusClassName(statement.status)}`}>
                              {titleCase(statement.status)}
                            </div>
                            {statement.timestamp ? (
                              <div className="mt-1 text-xs text-(--color-muted)">{formatTimestamp(statement.timestamp)}</div>
                            ) : null}
                          </div>
                        </div>
                        <div className="mt-3 grid gap-3 md:grid-cols-3">
                          {statement.justification ? (
                            <MetadataItem label="Justification" value={statement.justification} />
                          ) : null}
                          {statement.actionStatement ? (
                            <MetadataItem label="Action" value={statement.actionStatement} />
                          ) : null}
                          {statement.impactStatement ? (
                            <MetadataItem label="Impact" value={statement.impactStatement} />
                          ) : null}
                        </div>
                      </div>
                    ))}
                  </div>

                  <details className="mt-4 rounded-lg border border-(--color-border) bg-white/4 px-3 py-3">
                    <summary className="cursor-pointer text-sm font-medium text-(--color-text)">Raw document JSON</summary>
                    <pre className="mt-3 max-h-72 overflow-x-auto rounded-md bg-black/20 px-3 py-2 text-xs text-(--color-text)">
                      {JSON.stringify(selectedDocument.document, null, 2)}
                    </pre>
                  </details>
                </>
              ) : null}
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
}