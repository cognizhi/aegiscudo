import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  downloadTenantSbom,
  fetchAuditEvents,
  fetchDepsDdevPackages,
  fetchIocRecords,
  fetchPolicyScorecardThresholds,
  fetchTenantSboms,
} from "@/lib/control-plane";

describe("control-plane client helpers", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uses the persisted mock persona actor header when no persona is passed", async () => {
    localStorage.setItem("aegiscudo-mock-persona", "ciso-auditor");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await fetchAuditEvents("tenant-a");

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/tenants/tenant-a/audit-events"),
      expect.objectContaining({
        cache: "no-store",
        headers: {
          "x-aegiscudo-actor-id": "018f4a6f-55d0-7000-8000-000000000023",
        },
      }),
    );
  });

  it("uses the persisted mock persona actor header for tenant SBOM list fetches", async () => {
    localStorage.setItem("aegiscudo-mock-persona", "ciso-auditor");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("[]", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await fetchTenantSboms("tenant-a", { limit: 5 });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/tenants/tenant-a/analysis/sboms?limit=5",
      expect.objectContaining({
        cache: "no-store",
        headers: {
          "x-aegiscudo-actor-id": "018f4a6f-55d0-7000-8000-000000000023",
        },
      }),
    );
  });

  it("uses the persisted mock persona actor header for tenant SBOM downloads", async () => {
    localStorage.setItem("aegiscudo-mock-persona", "ciso-auditor");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('{"bomFormat":"CycloneDX"}', {
        status: 200,
        headers: {
          "content-type": "application/json",
          "content-disposition": 'attachment; filename="cargo-lock.json"',
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const download = await downloadTenantSbom("tenant-a", "sbom-1");

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/tenants/tenant-a/analysis/sboms/sbom-1",
      expect.objectContaining({
        cache: "no-store",
        headers: {
          "x-aegiscudo-actor-id": "018f4a6f-55d0-7000-8000-000000000023",
        },
      }),
    );
    expect(download.fileName).toBe("cargo-lock.json");
    expect(download.contentType).toBe("application/json");
  });

  it("uses the persisted mock persona actor header for scorecard threshold fetches", async () => {
    localStorage.setItem("aegiscudo-mock-persona", "ciso-auditor");
    const mockThresholds = {
      policy_profile_id: "profile-1",
      policy_version_id: "version-1",
      code_review: { min_score: 7.0, action: "block", enabled: true },
      branch_protection: { min_score: 6.0, action: "warn", enabled: true },
      ci_cd: { min_score: 5.0, action: "warn", enabled: true },
      maintained: { min_score: 4.0, action: "warn", enabled: false },
      signed_releases: { min_score: 0.0, action: "allow", enabled: false },
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(mockThresholds), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await fetchPolicyScorecardThresholds("tenant-a", "profile-1");

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/tenants/tenant-a/policy-profiles/profile-1/scorecard-thresholds",
      expect.objectContaining({
        cache: "no-store",
        headers: {
          "x-aegiscudo-actor-id": "018f4a6f-55d0-7000-8000-000000000023",
        },
      }),
    );
  });

  it("uses the persisted mock persona actor header for deps-dev package fetches", async () => {
    localStorage.setItem("aegiscudo-mock-persona", "ciso-auditor");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ packages: [], total: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await fetchDepsDdevPackages("tenant-a", { limit: 10, ecosystem: "npm" });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/tenants/tenant-a/deps-dev/packages?limit=10&ecosystem=npm",
      expect.objectContaining({
        cache: "no-store",
        headers: {
          "x-aegiscudo-actor-id": "018f4a6f-55d0-7000-8000-000000000023",
        },
      }),
    );
  });

  it("uses the persisted mock persona actor header for IOC records fetches", async () => {
    localStorage.setItem("aegiscudo-mock-persona", "ciso-auditor");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ records: [], total: 0 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await fetchIocRecords("tenant-a", { limit: 10, indicator_type: "domain" });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/tenants/tenant-a/ioc-records?limit=10&indicator_type=domain",
      expect.objectContaining({
        cache: "no-store",
        headers: {
          "x-aegiscudo-actor-id": "018f4a6f-55d0-7000-8000-000000000023",
        },
      }),
    );
  });
});