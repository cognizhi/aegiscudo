import { describe, expect, it } from "vitest";

import {
  DEFAULT_PERSONA_ID,
  MOCK_PERSONAS,
  getActorId,
  getPersona,
} from "@/lib/mock-personas";

describe("mock personas", () => {
  it("defines four seeded personas", () => {
    expect(MOCK_PERSONAS).toHaveLength(4);
    const ids = MOCK_PERSONAS.map((p) => p.id);
    expect(ids).toContain("developer");
    expect(ids).toContain("security-specialist");
    expect(ids).toContain("platform-admin");
    expect(ids).toContain("ciso-auditor");
  });

  it("default persona is platform-admin", () => {
    expect(DEFAULT_PERSONA_ID).toBe("platform-admin");
  });

  it("platform-admin has access to all nav sections", () => {
    const admin = getPersona("platform-admin");
    expect(admin.allowedSections).toContain("overview");
    expect(admin.allowedSections).toContain("analysis");
    expect(admin.allowedSections).toContain("policy");
    expect(admin.allowedSections).toContain("feeds");
    expect(admin.allowedSections).toContain("admin");
  });

  it("developer does not have admin section access", () => {
    const dev = getPersona("developer");
    expect(dev.allowedSections).not.toContain("admin");
    expect(dev.allowedSections).toContain("overview");
    expect(dev.allowedSections).toContain("analysis");
  });

  it("security-specialist does not have feeds or admin section access", () => {
    const specialist = getPersona("security-specialist");
    expect(specialist.allowedSections).not.toContain("feeds");
    expect(specialist.allowedSections).not.toContain("admin");
    expect(specialist.allowedSections).toContain("analysis");
  });

  it("ciso-auditor only has overview and admin section access", () => {
    const ciso = getPersona("ciso-auditor");
    expect(ciso.allowedSections).toContain("overview");
    expect(ciso.allowedSections).toContain("admin");
    expect(ciso.allowedSections).not.toContain("analysis");
    expect(ciso.allowedSections).not.toContain("policy");
    expect(ciso.allowedSections).not.toContain("feeds");
  });

  it("each persona has a distinct actor ID matching a seeded fixture UUID", () => {
    const actorIds = MOCK_PERSONAS.map((p) => p.actorId);
    const unique = new Set(actorIds);
    expect(unique.size).toBe(MOCK_PERSONAS.length);
    for (const id of actorIds) {
      // Validate UUID v7-like format: 018f4a6f-55d0-7000-8000-00000000xxxx
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
    }
  });

  it("getActorId returns the persona actor ID", () => {
    expect(getActorId("platform-admin")).toBe("018f4a6f-55d0-7000-8000-000000000011");
    expect(getActorId("developer")).toBe("018f4a6f-55d0-7000-8000-000000000021");
    expect(getActorId("security-specialist")).toBe("018f4a6f-55d0-7000-8000-000000000022");
    expect(getActorId("ciso-auditor")).toBe("018f4a6f-55d0-7000-8000-000000000023");
  });

  it("getPersona falls back to platform-admin for unknown id", () => {
    // Type assertion to simulate bad runtime input
    const persona = getPersona("unknown" as Parameters<typeof getPersona>[0]);
    expect(persona.id).toBe("platform-admin");
  });
});
