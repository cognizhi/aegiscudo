import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GET as getRequestTimeline } from "@/app/api/tenants/[tenantId]/analysis/request-timeline/route";
import { POST as approveOverride } from "@/app/api/tenants/[tenantId]/overrides/[overrideId]/approve/route";
import { POST as denyOverride } from "@/app/api/tenants/[tenantId]/overrides/[overrideId]/deny/route";
import { GET as getOverrides } from "@/app/api/tenants/[tenantId]/overrides/route";
import { GET as getArtifactEvidence } from "@/app/api/tenants/[tenantId]/artifacts/[artifactId]/evidence/route";
import { GET as getQuarantineQueue } from "@/app/api/tenants/[tenantId]/analysis/quarantine-queue/route";
import { getDefaultActorId, proxyControlPlaneJson } from "@/lib/control-plane";

const defaultProxyHeaders = {
  accept: "application/json",
  "x-aegiscudo-actor-id": getDefaultActorId(),
};

describe("control-plane proxy routes", () => {
  beforeEach(() => {
    process.env.AEGISCUDO_API_BASE_URL = "http://api.test:8082";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.AEGISCUDO_API_BASE_URL;
  });

  it("forwards upstream JSON and status codes", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ trace_id: "trace-quarantine-002" }]), {
        status: 202,
        headers: { "content-type": "application/json; charset=utf-8" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await proxyControlPlaneJson("/v1/tenants/tenant-a/analysis/quarantine-queue");

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/analysis/quarantine-queue",
      {
        cache: "no-store",
        headers: defaultProxyHeaders,
      },
    );
    expect(response.status).toBe(202);
    await expect(response.json()).resolves.toEqual([{ trace_id: "trace-quarantine-002" }]);
  });

  it("returns a 503 JSON error when the upstream API is unavailable", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("connect ECONNREFUSED 127.0.0.1:8082"));
    vi.stubGlobal("fetch", fetchMock);

    const response = await proxyControlPlaneJson("/v1/tenants/tenant-a/analysis/quarantine-queue");

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      message: "connect ECONNREFUSED 127.0.0.1:8082",
    });
  });

  it("forwards JSON request bodies for writable override actions", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "override-1", status: "approved" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await proxyControlPlaneJson("/v1/tenants/tenant-a/overrides/override-1/approve", {
      method: "POST",
      body: { reason: "Incident approved", actor_id: "user-1" },
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/overrides/override-1/approve",
      {
        cache: "no-store",
        method: "POST",
        headers: {
          ...defaultProxyHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({ reason: "Incident approved", actor_id: "user-1" }),
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ id: "override-1", status: "approved" });
  });

  it("proxies the quarantine queue route with the tenant path", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getQuarantineQueue(new Request("http://localhost/api"), {
      params: Promise.resolve({ tenantId: "tenant-a" }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/analysis/quarantine-queue",
      {
        cache: "no-store",
        headers: defaultProxyHeaders,
      },
    );
    expect(response.status).toBe(200);
  });

  it("proxies the request timeline route with the tenant path", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ bucket_start: "2026-05-05T10:00:00Z", allow: 1, warn: 0, quarantine: 1, block: 0 }]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getRequestTimeline(new Request("http://localhost/api"), {
      params: Promise.resolve({ tenantId: "tenant-a" }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/analysis/request-timeline",
      {
        cache: "no-store",
        headers: defaultProxyHeaders,
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual([
      { bucket_start: "2026-05-05T10:00:00Z", allow: 1, warn: 0, quarantine: 1, block: 0 },
    ]);
  });

  it("proxies the override queue route with the tenant path", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ id: "override-1", status: "pending", reason: "Temporary analyst review bypass", scope: {} }]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getOverrides(new Request("http://localhost/api"), {
      params: Promise.resolve({ tenantId: "tenant-a" }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/overrides",
      {
        cache: "no-store",
        headers: defaultProxyHeaders,
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual([
      { id: "override-1", status: "pending", reason: "Temporary analyst review bypass", scope: {} },
    ]);
  });

  it("proxies the override approval route with the tenant and override path", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "override-1", status: "approved" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await approveOverride(
      new Request("http://localhost/api", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reason: "Incident approved", actor_id: "user-1" }),
      }),
      {
        params: Promise.resolve({ tenantId: "tenant-a", overrideId: "override-1" }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/overrides/override-1/approve",
      {
        cache: "no-store",
        method: "POST",
        headers: {
          ...defaultProxyHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({ reason: "Incident approved", actor_id: "user-1" }),
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ id: "override-1", status: "approved" });
  });

  it("proxies the override denial route with the tenant and override path", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "override-1", status: "denied" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await denyOverride(
      new Request("http://localhost/api", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reason: "Denied for incident scope mismatch", actor_id: "user-1" }),
      }),
      {
        params: Promise.resolve({ tenantId: "tenant-a", overrideId: "override-1" }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/overrides/override-1/deny",
      {
        cache: "no-store",
        method: "POST",
        headers: {
          ...defaultProxyHeaders,
          "content-type": "application/json",
        },
        body: JSON.stringify({ reason: "Denied for incident scope mismatch", actor_id: "user-1" }),
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ id: "override-1", status: "denied" });
  });

  it("proxies the artifact evidence route with the tenant and artifact path", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ trace_id: "trace-block-003" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getArtifactEvidence(new Request("http://localhost/api"), {
      params: Promise.resolve({
        tenantId: "tenant-a",
        artifactId: "artifact-42",
      }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/artifacts/artifact-42/evidence",
      {
        cache: "no-store",
        headers: defaultProxyHeaders,
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ trace_id: "trace-block-003" });
  });

  it("forwards a non-default actor ID from the incoming request header (mock-auth persona switching)", async () => {
    const devActorId = "018f4a6f-55d0-7000-8000-000000000021";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const incomingRequest = new Request("http://localhost/api", {
      headers: { "x-aegiscudo-actor-id": devActorId },
    });

    const response = await getQuarantineQueue(incomingRequest, {
      params: Promise.resolve({ tenantId: "tenant-a" }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/analysis/quarantine-queue",
      {
        cache: "no-store",
        headers: {
          accept: "application/json",
          "x-aegiscudo-actor-id": devActorId,
        },
      },
    );
    expect(response.status).toBe(200);
  });

  it("uses default actor when no actor header is in the incoming request", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getQuarantineQueue(new Request("http://localhost/api"), {
      params: Promise.resolve({ tenantId: "tenant-a" }),
    });

    const calledHeaders = (fetchMock.mock.calls[0] as [string, RequestInit])[1].headers as Record<string, string>;
    expect(calledHeaders["x-aegiscudo-actor-id"]).toBe(getDefaultActorId());
  });
});