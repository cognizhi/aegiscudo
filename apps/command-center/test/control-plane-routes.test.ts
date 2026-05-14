import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GET as getOpenVexDocument } from "@/app/api/tenants/[tenantId]/analysis/openvex-documents/[openVexDocumentId]/route";
import { GET as getOpenVexDocuments } from "@/app/api/tenants/[tenantId]/analysis/openvex-documents/route";
import { GET as getTenantSbom } from "@/app/api/tenants/[tenantId]/analysis/sboms/[sbomId]/route";
import { GET as getTenantSboms } from "@/app/api/tenants/[tenantId]/analysis/sboms/route";
import { GET as getRequestTimeline } from "@/app/api/tenants/[tenantId]/analysis/request-timeline/route";
import { POST as approveOverride } from "@/app/api/tenants/[tenantId]/overrides/[overrideId]/approve/route";
import { POST as denyOverride } from "@/app/api/tenants/[tenantId]/overrides/[overrideId]/deny/route";
import { GET as getOverrides } from "@/app/api/tenants/[tenantId]/overrides/route";
import { GET as getArtifactEvidence } from "@/app/api/tenants/[tenantId]/artifacts/[artifactId]/evidence/route";
import { GET as getQuarantineQueue } from "@/app/api/tenants/[tenantId]/analysis/quarantine-queue/route";
import { GET as getDepsDdevPackages } from "@/app/api/tenants/[tenantId]/deps-dev/packages/route";
import { GET as getIocRecords } from "@/app/api/tenants/[tenantId]/ioc-records/route";
import { GET as getScorecardThresholds } from "@/app/api/tenants/[tenantId]/policy-profiles/[policyProfileId]/scorecard-thresholds/route";
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

  it("proxies the tenant SBOM list route through the control-plane API", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ id: "sbom-1", source: "Cargo.lock" }]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getTenantSboms(
      new Request("http://localhost/api?limit=5", {
        headers: { "x-aegiscudo-actor-id": "actor-override" },
      }),
      {
        params: Promise.resolve({ tenantId: "tenant-a" }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/sboms?limit=5",
      {
        cache: "no-store",
        headers: {
          ...defaultProxyHeaders,
          "x-aegiscudo-actor-id": "actor-override",
        },
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual([{ id: "sbom-1", source: "Cargo.lock" }]);
  });

  it("proxies the tenant OpenVEX list route through the control-plane API", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ id: "openvex-1", source: "fixture-openvex.json" }]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getOpenVexDocuments(
      new Request("http://localhost/api", {
        headers: { "x-aegiscudo-actor-id": "actor-override" },
      }),
      {
        params: Promise.resolve({ tenantId: "tenant-a" }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/openvex-documents",
      {
        cache: "no-store",
        headers: {
          ...defaultProxyHeaders,
          "x-aegiscudo-actor-id": "actor-override",
        },
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual([{ id: "openvex-1", source: "fixture-openvex.json" }]);
  });

  it("proxies the tenant SBOM download route through the control-plane API", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('{"bomFormat":"CycloneDX"}', {
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-disposition": 'attachment; filename="cargo-lock.json"',
          "cache-control": "private, max-age=60",
          etag: '"sbom-1"',
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getTenantSbom(
      new Request("http://localhost/api", {
        headers: { "x-aegiscudo-actor-id": "actor-override" },
      }),
      {
        params: Promise.resolve({ tenantId: "tenant-a", sbomId: "sbom-1" }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/sboms/sbom-1",
      {
        cache: "no-store",
        headers: {
          ...defaultProxyHeaders,
          "x-aegiscudo-actor-id": "actor-override",
        },
      },
    );
    expect(response.headers.get("content-disposition")).toBe('attachment; filename="cargo-lock.json"');
    expect(response.headers.get("cache-control")).toBe("private, max-age=60");
    expect(response.headers.get("etag")).toBe('"sbom-1"');
    await expect(response.text()).resolves.toBe('{"bomFormat":"CycloneDX"}');
  });

  it("forwards a non-default actor ID for the OpenVEX detail route", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "openvex-1", document: { statements: [] } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getOpenVexDocument(
      new Request("http://localhost/api", {
        headers: { "x-aegiscudo-actor-id": "actor-override" },
      }),
      {
        params: Promise.resolve({ tenantId: "tenant-a", openVexDocumentId: "openvex-1" }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/openvex-documents/openvex-1",
      {
        cache: "no-store",
        headers: {
          ...defaultProxyHeaders,
          "x-aegiscudo-actor-id": "actor-override",
        },
      },
    );
    expect(response.status).toBe(200);
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

  it("forwards a non-default actor ID for the artifact evidence route", async () => {
    const reviewerActorId = "018f4a6f-55d0-7000-8000-000000000023";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ trace_id: "trace-cargo-001" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getArtifactEvidence(
      new Request("http://localhost/api", {
        headers: { "x-aegiscudo-actor-id": reviewerActorId },
      }),
      {
        params: Promise.resolve({
          tenantId: "tenant-a",
          artifactId: "artifact-42",
        }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/tenant-a/artifacts/artifact-42/evidence",
      {
        cache: "no-store",
        headers: {
          accept: "application/json",
          "x-aegiscudo-actor-id": reviewerActorId,
        },
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ trace_id: "trace-cargo-001" });
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

  it("proxies the scorecard-thresholds route with tenant and policy-profile path segments", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          policy_profile_id: "profile-1",
          policy_version_id: "version-1",
          code_review: { min_score: 7.0, action: "block", enabled: true },
          branch_protection: { min_score: 6.0, action: "warn", enabled: true },
          ci_cd: { min_score: 5.0, action: "warn", enabled: true },
          maintained: { min_score: 4.0, action: "warn", enabled: false },
          signed_releases: { min_score: 0.0, action: "allow", enabled: false },
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getScorecardThresholds(new Request("http://localhost/api"), {
      params: Promise.resolve({
        tenantId: "018f4a6f-0000-0000-0000-000000000001",
        policyProfileId: "018f4a6f-0000-0000-0000-000000000002",
      }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/018f4a6f-0000-0000-0000-000000000001/policy-profiles/018f4a6f-0000-0000-0000-000000000002/scorecard-thresholds",
      {
        cache: "no-store",
        headers: defaultProxyHeaders,
      },
    );
    expect(response.status).toBe(200);
    const body = await response.json() as { code_review: { min_score: number } };
    expect(body.code_review.min_score).toBe(7.0);
  });

  it("rejects scorecard-thresholds route with non-UUID path parameters", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await getScorecardThresholds(new Request("http://localhost/api"), {
      params: Promise.resolve({ tenantId: "tenant-a", policyProfileId: "profile-1" }),
    });

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards the actor header for the scorecard-thresholds route", async () => {
    const reviewerActorId = "018f4a6f-55d0-7000-8000-000000000023";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({}), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getScorecardThresholds(
      new Request("http://localhost/api", {
        headers: { "x-aegiscudo-actor-id": reviewerActorId },
      }),
      {
        params: Promise.resolve({
          tenantId: "018f4a6f-0000-0000-0000-000000000001",
          policyProfileId: "018f4a6f-0000-0000-0000-000000000002",
        }),
      },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://api.test:8082/v1/tenants/018f4a6f-0000-0000-0000-000000000001/policy-profiles/018f4a6f-0000-0000-0000-000000000002/scorecard-thresholds",
      {
        cache: "no-store",
        headers: {
          accept: "application/json",
          "x-aegiscudo-actor-id": reviewerActorId,
        },
      },
    );
  });

  it("proxies the deps-dev packages route with tenant path", async () => {
    const tenantUuid = "018f4a6f-0000-0000-0000-000000000001";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ packages: [], total: 0, snapshot_taken_at: null }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await getDepsDdevPackages(
      new Request(`http://localhost/api/tenants/${tenantUuid}/deps-dev/packages`),
      { params: Promise.resolve({ tenantId: tenantUuid }) },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      `http://api.test:8082/v1/tenants/${tenantUuid}/deps-dev/packages`,
      { cache: "no-store", headers: defaultProxyHeaders },
    );
    expect(response.status).toBe(200);
  });

  it("forwards query parameters on the deps-dev packages route", async () => {
    const tenantUuid = "018f4a6f-0000-0000-0000-000000000001";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ packages: [], total: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getDepsDdevPackages(
      new Request(`http://localhost/api/tenants/${tenantUuid}/deps-dev/packages?limit=10&ecosystem=npm`),
      { params: Promise.resolve({ tenantId: tenantUuid }) },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      `http://api.test:8082/v1/tenants/${tenantUuid}/deps-dev/packages?limit=10&ecosystem=npm`,
      { cache: "no-store", headers: defaultProxyHeaders },
    );
  });

  it("rejects deps-dev packages route with a non-UUID tenant", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await getDepsDdevPackages(
      new Request("http://localhost/api/tenants/bad-tenant/deps-dev/packages"),
      { params: Promise.resolve({ tenantId: "bad-tenant" }) },
    );

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("proxies ioc-records route with tenant path", async () => {
    const tenantUuid = "018f4a6f-0000-0000-0000-000000000001";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ records: [], total: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getIocRecords(
      new Request(`http://localhost/api/tenants/${tenantUuid}/ioc-records`),
      { params: Promise.resolve({ tenantId: tenantUuid }) },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      `http://api.test:8082/v1/tenants/${tenantUuid}/ioc-records`,
      { cache: "no-store", headers: defaultProxyHeaders },
    );
  });

  it("forwards indicator_type query parameter on ioc-records route", async () => {
    const tenantUuid = "018f4a6f-0000-0000-0000-000000000001";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ records: [], total: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await getIocRecords(
      new Request(`http://localhost/api/tenants/${tenantUuid}/ioc-records?limit=10&indicator_type=domain`),
      { params: Promise.resolve({ tenantId: tenantUuid }) },
    );

    expect(fetchMock).toHaveBeenCalledWith(
      `http://api.test:8082/v1/tenants/${tenantUuid}/ioc-records?limit=10&indicator_type=domain`,
      { cache: "no-store", headers: defaultProxyHeaders },
    );
  });

  it("rejects ioc-records route with a non-UUID tenant", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await getIocRecords(
      new Request("http://localhost/api/tenants/bad-tenant/ioc-records"),
      { params: Promise.resolve({ tenantId: "bad-tenant" }) },
    );

    expect(response.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});