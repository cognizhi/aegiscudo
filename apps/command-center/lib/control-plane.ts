import type {
  AiProviderConfig,
  ArtifactEvidence,
  DashboardMetrics,
  ConnectionTestResult,
  CredentialStatus,
  DepsDdevPackagesResponse,
  GithubActionsScanResult,
  IocRecordsResponse,
  InvestigationAuditEvent,
  LlmUsage,
  OpenVexDocument,
  OpenVexDocumentSummary,
  OverrideActionRequest,
  OverrideQueueItem,
  OverrideResponse,
  PolicyProfileSummary,
  PolicyScorecardThresholds,
  PolicySimulationRequest,
  PolicySimulationResult,
  QuarantineQueueItem,
  RegistryConfig,
  RequestTimelineBucket,
  SbomDocumentSummary,
  SbomNtiaValidation,
} from "@aegiscudo/shared-types";
import { getActorId, loadPersistedPersonaId } from "@/lib/mock-personas";
import type { PersonaId } from "@/lib/mock-personas";

const fixtureTenantId = "018f4a6f-55d0-7000-8000-000000000001";
const fixtureActorId = "018f4a6f-55d0-7000-8000-000000000011";
const defaultApiBaseUrl = "http://127.0.0.1:18002";
const actorHeader = "x-aegiscudo-actor-id";
const proxiedDownloadHeaders = [
  "content-type",
  "content-disposition",
  "content-length",
  "cache-control",
  "etag",
  "content-encoding",
] as const;

export type SbomNtiaValidationResult = SbomNtiaValidation;

export type TenantSbomDocument = SbomDocumentSummary;

export type TenantOpenVexDocumentSummary = OpenVexDocumentSummary;

export type TenantOpenVexDocument = OpenVexDocument;

export interface TenantSbomDownload {
  blob: Blob;
  fileName: string | null;
  contentType: string;
}

export function getDefaultTenantId(): string {
  return process.env.NEXT_PUBLIC_AEGISCUDO_TENANT_ID ?? fixtureTenantId;
}

export function getDefaultActorId(): string {
  return process.env.NEXT_PUBLIC_AEGISCUDO_ACTOR_ID ?? fixtureActorId;
}

function resolveActorId(personaId?: PersonaId): string {
  if (personaId) {
    return getActorId(personaId);
  }
  if (typeof window !== "undefined") {
    return getActorId(loadPersistedPersonaId());
  }
  return getDefaultActorId();
}

/** Build headers including the active mock persona's actor ID for local dev auth. */
function actorHeaders(personaId?: PersonaId): HeadersInit {
  const actorId = resolveActorId(personaId);
  return { [actorHeader]: actorId };
}

function controlPlaneApiBaseUrl(): string {
  return (
    process.env.AEGISCUDO_API_BASE_URL ??
    process.env.NEXT_PUBLIC_AEGISCUDO_API_BASE_URL ??
    defaultApiBaseUrl
  );
}

export async function fetchQuarantineQueue(tenantId: string, personaId?: PersonaId): Promise<QuarantineQueueItem[]> {
  const response = await fetch(`/api/tenants/${tenantId}/analysis/quarantine-queue`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<QuarantineQueueItem[]>(response);
}

export async function fetchRequestTimeline(tenantId: string, personaId?: PersonaId): Promise<RequestTimelineBucket[]> {
  const response = await fetch(`/api/tenants/${tenantId}/analysis/request-timeline`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<RequestTimelineBucket[]>(response);
}

export async function fetchDashboardMetrics(tenantId: string, personaId?: PersonaId): Promise<DashboardMetrics> {
  const response = await fetch(`/api/tenants/${tenantId}/analysis/dashboard-metrics`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<DashboardMetrics>(response);
}

export async function fetchTenantSboms(
  tenantId: string,
  options: { limit?: number } = {},
  personaId?: PersonaId,
): Promise<TenantSbomDocument[]> {
  const search =
    options.limit !== undefined ? `?limit=${encodeURIComponent(String(options.limit))}` : "";
  const response = await fetch(`/api/tenants/${tenantId}/analysis/sboms${search}`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<TenantSbomDocument[]>(response);
}

export async function downloadTenantSbom(
  tenantId: string,
  sbomId: string,
  personaId?: PersonaId,
): Promise<TenantSbomDownload> {
  const response = await fetch(`/api/tenants/${tenantId}/analysis/sboms/${sbomId}`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });

  if (!response.ok) {
    throw new Error(await readErrorMessage(response));
  }

  return {
    blob: await response.blob(),
    fileName: parseContentDispositionFilename(
      response.headers.get("content-disposition"),
    ),
    contentType: response.headers.get("content-type") ?? "application/json",
  };
}

export async function fetchTenantOpenVexDocuments(
  tenantId: string,
  personaId?: PersonaId,
): Promise<TenantOpenVexDocumentSummary[]> {
  const response = await fetch(`/api/tenants/${tenantId}/analysis/openvex-documents`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<TenantOpenVexDocumentSummary[]>(response);
}

export async function fetchTenantOpenVexDocument(
  tenantId: string,
  openVexDocumentId: string,
  personaId?: PersonaId,
): Promise<TenantOpenVexDocument> {
  const response = await fetch(
    `/api/tenants/${tenantId}/analysis/openvex-documents/${openVexDocumentId}`,
    {
      cache: "no-store",
      headers: actorHeaders(personaId),
    },
  );
  return readJsonResponse<TenantOpenVexDocument>(response);
}

export async function fetchPolicyProfiles(tenantId: string, personaId?: PersonaId): Promise<PolicyProfileSummary[]> {
  const response = await fetch(`/api/tenants/${tenantId}/policy-profiles`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<PolicyProfileSummary[]>(response);
}

export async function fetchPolicyScorecardThresholds(
  tenantId: string,
  policyProfileId: string,
  personaId?: PersonaId,
): Promise<PolicyScorecardThresholds> {
  const response = await fetch(
    `/api/tenants/${tenantId}/policy-profiles/${policyProfileId}/scorecard-thresholds`,
    {
      cache: "no-store",
      headers: actorHeaders(personaId),
    },
  );
  return readJsonResponse<PolicyScorecardThresholds>(response);
}

export async function fetchDepsDdevPackages(
  tenantId: string,
  params?: { limit?: number; ecosystem?: string },
  personaId?: PersonaId,
): Promise<DepsDdevPackagesResponse> {
  const query = new URLSearchParams();
  if (params?.limit !== undefined) query.set("limit", String(params.limit));
  if (params?.ecosystem) query.set("ecosystem", params.ecosystem);
  const qs = query.size > 0 ? `?${query.toString()}` : "";
  const response = await fetch(`/api/tenants/${tenantId}/deps-dev/packages${qs}`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<DepsDdevPackagesResponse>(response);
}

export async function fetchIocRecords(
  tenantId: string,
  params?: { limit?: number; indicator_type?: string },
  personaId?: PersonaId,
): Promise<IocRecordsResponse> {
  const query = new URLSearchParams();
  if (params?.limit !== undefined) query.set("limit", String(params.limit));
  if (params?.indicator_type) query.set("indicator_type", params.indicator_type);
  const qs = query.size > 0 ? `?${query.toString()}` : "";
  const response = await fetch(`/api/tenants/${tenantId}/ioc-records${qs}`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<IocRecordsResponse>(response);
}

export async function fetchGithubActionsScanResults(
  tenantId: string,
  params?: { limit?: number },
  personaId?: PersonaId,
): Promise<GithubActionsScanResult[]> {
  const query = new URLSearchParams();
  if (params?.limit !== undefined) query.set("limit", String(params.limit));
  const qs = query.size > 0 ? `?${query.toString()}` : "";
  const response = await fetch(
    `/api/tenants/${tenantId}/github-actions/scan-results${qs}`,
    { cache: "no-store", headers: actorHeaders(personaId) },
  );
  return readJsonResponse<GithubActionsScanResult[]>(response);
}

export async function simulatePolicyReplay(
  tenantId: string,
  request: PolicySimulationRequest,
  personaId?: PersonaId,
): Promise<PolicySimulationResult> {
  const response = await fetch(`/api/tenants/${tenantId}/policy-simulator/replay`, {
    method: "POST",
    cache: "no-store",
    headers: {
      "content-type": "application/json",
      ...actorHeaders(personaId),
    },
    body: JSON.stringify(request),
  });
  return readJsonResponse<PolicySimulationResult>(response);
}

export async function fetchOverrides(tenantId: string, personaId?: PersonaId): Promise<OverrideQueueItem[]> {
  const response = await fetch(`/api/tenants/${tenantId}/overrides`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<OverrideQueueItem[]>(response);
}

export async function submitOverrideDecision(
  tenantId: string,
  overrideId: string,
  action: "approve" | "deny",
  request: OverrideActionRequest,
): Promise<OverrideResponse> {
  const response = await fetch(`/api/tenants/${tenantId}/overrides/${overrideId}/${action}`, {
    method: "POST",
    cache: "no-store",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      ...request,
      actor_id: request.actor_id ?? resolveActorId(),
      reason: request.reason.trim(),
    }),
  });
  return readJsonResponse<OverrideResponse>(response);
}

export async function fetchArtifactEvidence(
  tenantId: string,
  artifactId: string,
  personaId?: PersonaId,
): Promise<ArtifactEvidence> {
  const response = await fetch(`/api/tenants/${tenantId}/artifacts/${artifactId}/evidence`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<ArtifactEvidence>(response);
}

interface ProxyControlPlaneJsonOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  headers?: HeadersInit;
  /** When provided, the actor header from this request takes precedence over the default. */
  incomingRequest?: Request;
}

export async function proxyControlPlaneJson(
  pathname: string,
  options: ProxyControlPlaneJsonOptions = {},
): Promise<Response> {
  return proxyJsonService(
    controlPlaneApiBaseUrl(),
    pathname,
    options,
    "Unable to reach the Aegiscudo API investigation endpoints.",
  );
}

async function proxyJsonService(
  baseUrl: string,
  pathname: string,
  options: ProxyControlPlaneJsonOptions,
  unavailableMessage: string,
): Promise<Response> {
  try {
    const headers: Record<string, string> = {
      accept: "application/json",
    };
    if (options.headers) {
      const forwardedHeaders = new Headers(options.headers);
      forwardedHeaders.forEach((value, key) => {
        headers[key] = value;
      });
    }
    // Prefer actor header forwarded from the browser (local mock-auth persona) over default.
    const incomingActorId = options.incomingRequest?.headers.get(actorHeader);
    if (headers[actorHeader] === undefined) {
      headers[actorHeader] = incomingActorId ?? getDefaultActorId();
    }
    if (options.body !== undefined && headers["content-type"] === undefined) {
      headers["content-type"] = "application/json";
    }
    const requestInit: RequestInit = {
      cache: "no-store",
      headers,
    };
    const method = options.method ?? (options.body === undefined ? "GET" : "POST");
    if (method !== "GET") {
      requestInit.method = method;
    }
    if (options.body !== undefined) {
      requestInit.body = JSON.stringify(options.body);
    }
    const upstream = await fetch(`${baseUrl.replace(/\/$/, "")}${pathname}`, requestInit);
    const responseHeaders = new Headers();
    for (const headerName of proxiedDownloadHeaders) {
      const value = upstream.headers.get(headerName);
      if (value !== null) {
        responseHeaders.set(headerName, value);
      }
    }
    if (!responseHeaders.has("content-type")) {
      responseHeaders.set("content-type", "application/json");
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : unavailableMessage;
    return Response.json({ message }, { status: 503 });
  }
}

async function readJsonResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(await readErrorMessage(response));
  }
  return (await response.json()) as T;
}

async function readErrorMessage(response: Response): Promise<string> {
  let message = `Request failed with status ${response.status}`;
  try {
    const errorBody = (await response.json()) as { message?: string };
    if (typeof errorBody.message === "string" && errorBody.message.trim()) {
      message = errorBody.message;
    }
  } catch {
    // Ignore JSON parse failures and keep the generic message.
  }
  return message;
}

function parseContentDispositionFilename(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const encodedMatch = value.match(/filename\*=UTF-8''([^;]+)/i);
  if (encodedMatch?.[1]) {
    try {
      return decodeURIComponent(encodedMatch[1]);
    } catch {
      // Fall through to the plain filename parser.
    }
  }

  const plainMatch = value.match(/filename="?([^";]+)"?/i);
  return plainMatch?.[1] ?? null;
}

export async function fetchRegistryConfigs(tenantId: string, personaId?: PersonaId): Promise<RegistryConfig[]> {
  const response = await fetch(`/api/tenants/${tenantId}/registry-configs`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<RegistryConfig[]>(response);
}

export async function deleteRegistryConfig(
  tenantId: string,
  registryConfigId: string,
  personaId?: PersonaId,
): Promise<void> {
  const response = await fetch(
    `/api/tenants/${tenantId}/registry-configs/${registryConfigId}`,
    { method: "DELETE", cache: "no-store", headers: actorHeaders(personaId) },
  );
  if (!response.ok && response.status !== 204) {
    throw new Error(`Delete failed with status ${response.status}`);
  }
}

export async function fetchCredentials(tenantId: string, personaId?: PersonaId): Promise<CredentialStatus[]> {
  const response = await fetch(`/api/tenants/${tenantId}/credentials`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<CredentialStatus[]>(response);
}

export async function testCredentialConnection(
  tenantId: string,
  credentialId: string,
  personaId?: PersonaId,
): Promise<ConnectionTestResult> {
  const response = await fetch(
    `/api/tenants/${tenantId}/credentials/${credentialId}/test-connection`,
    { method: "POST", cache: "no-store", headers: actorHeaders(personaId) },
  );
  return readJsonResponse<ConnectionTestResult>(response);
}

export async function deleteCredential(
  tenantId: string,
  credentialId: string,
  personaId?: PersonaId,
): Promise<void> {
  const response = await fetch(`/api/tenants/${tenantId}/credentials/${credentialId}`, {
    method: "DELETE",
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  if (!response.ok && response.status !== 204) {
    throw new Error(`Delete failed with status ${response.status}`);
  }
}

export async function fetchAuditEvents(
  tenantId: string,
  params: { action?: string; actor?: string; limit?: number } = {},
  personaId?: PersonaId,
): Promise<InvestigationAuditEvent[]> {
  const url = new URL(`/api/tenants/${tenantId}/audit-events`, window.location.origin);
  if (params.action) url.searchParams.set("action", params.action);
  if (params.actor) url.searchParams.set("actor", params.actor);
  if (params.limit) url.searchParams.set("limit", String(params.limit));
  const response = await fetch(url.toString(), { cache: "no-store", headers: actorHeaders(personaId) });
  return readJsonResponse<InvestigationAuditEvent[]>(response);
}

export async function fetchAiProviders(tenantId: string, personaId?: PersonaId): Promise<AiProviderConfig[]> {
  const response = await fetch(`/api/tenants/${tenantId}/ai-providers`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<AiProviderConfig[]>(response);
}

export async function fetchLlmUsage(tenantId: string, personaId?: PersonaId): Promise<LlmUsage> {
  const response = await fetch(`/api/tenants/${tenantId}/llm-usage`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<LlmUsage>(response);
}