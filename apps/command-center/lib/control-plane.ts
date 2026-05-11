import type {
  AiProviderConfig,
  ArtifactEvidence,
  DashboardMetrics,
  ConnectionTestResult,
  CredentialStatus,
  InvestigationAuditEvent,
  LlmUsage,
  OverrideActionRequest,
  OverrideQueueItem,
  OverrideResponse,
  PolicyProfileSummary,
  PolicySimulationRequest,
  PolicySimulationResult,
  QuarantineQueueItem,
  RegistryConfig,
  RequestTimelineBucket,
} from "@aegiscudo/shared-types";
import { getActorId, loadPersistedPersonaId } from "@/lib/mock-personas";
import type { PersonaId } from "@/lib/mock-personas";

const fixtureTenantId = "018f4a6f-55d0-7000-8000-000000000001";
const fixtureActorId = "018f4a6f-55d0-7000-8000-000000000011";
const defaultApiBaseUrl = "http://127.0.0.1:18002";
const actorHeader = "x-aegiscudo-actor-id";

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

export async function fetchPolicyProfiles(tenantId: string, personaId?: PersonaId): Promise<PolicyProfileSummary[]> {
  const response = await fetch(`/api/tenants/${tenantId}/policy-profiles`, {
    cache: "no-store",
    headers: actorHeaders(personaId),
  });
  return readJsonResponse<PolicyProfileSummary[]>(response);
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
    const upstream = await fetch(`${controlPlaneApiBaseUrl().replace(/\/$/, "")}${pathname}`, requestInit);
    const body = await upstream.text();
    const contentDisposition = upstream.headers.get("content-disposition");
    return new Response(body, {
      status: upstream.status,
      headers: {
        "content-type": upstream.headers.get("content-type") ?? "application/json",
        ...(contentDisposition ? { "content-disposition": contentDisposition } : {}),
      },
    });
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : "Unable to reach the Aegiscudo API investigation endpoints.";
    return Response.json({ message }, { status: 503 });
  }
}

async function readJsonResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const errorBody = (await response.json()) as { message?: string };
      if (typeof errorBody.message === "string" && errorBody.message.trim()) {
        message = errorBody.message;
      }
    } catch {
      // Ignore JSON parse failures and keep the generic message.
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
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