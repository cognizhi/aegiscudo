import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fetchAuditEvents } from "@/lib/control-plane";

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
});