/**
 * Local dev mock personas.
 *
 * ADR 0005 — Local alpha uses mock OIDC with seeded personas only.
 * Backend RBAC is authoritative; UI navigation filtering is a secondary affordance.
 */

export type PersonaId =
  | "developer"
  | "security-specialist"
  | "platform-admin"
  | "ciso-auditor";

/** Navigation section keys that appear in the sidebar. */
export type NavSection = "overview" | "analysis" | "policy" | "feeds" | "admin";

export interface MockPersona {
  /** Stable identifier that maps to a seeded fixture actor in the control-plane DB. */
  id: PersonaId;
  /** Actor UUID forwarded as `x-aegiscudo-actor-id`. Must match a seeded `users` row. */
  actorId: string;
  displayName: string;
  email: string;
  /** Sections the persona has access to. Admin routes enforce RBAC server-side. */
  allowedSections: NavSection[];
}

export const MOCK_PERSONAS: MockPersona[] = [
  {
    id: "developer",
    actorId: "018f4a6f-55d0-7000-8000-000000000021",
    displayName: "Dev User",
    email: "dev@aegiscudo.invalid",
    allowedSections: ["overview", "analysis", "policy", "feeds"],
  },
  {
    id: "security-specialist",
    actorId: "018f4a6f-55d0-7000-8000-000000000022",
    displayName: "Security Specialist",
    email: "security@aegiscudo.invalid",
    allowedSections: ["overview", "analysis", "policy"],
  },
  {
    id: "platform-admin",
    actorId: "018f4a6f-55d0-7000-8000-000000000011",
    displayName: "Platform Admin",
    email: "local-admin@aegiscudo.invalid",
    allowedSections: ["overview", "analysis", "policy", "feeds", "admin"],
  },
  {
    id: "ciso-auditor",
    actorId: "018f4a6f-55d0-7000-8000-000000000023",
    displayName: "CISO / Auditor",
    email: "ciso@aegiscudo.invalid",
    allowedSections: ["overview", "admin"],
  },
];

export const DEFAULT_PERSONA_ID: PersonaId = "platform-admin";

const STORAGE_KEY = "aegiscudo-mock-persona";

export function loadPersistedPersonaId(): PersonaId {
  if (typeof window === "undefined") {
    return DEFAULT_PERSONA_ID;
  }
  const stored = localStorage.getItem(STORAGE_KEY);
  return (MOCK_PERSONAS.find((p) => p.id === stored)?.id ?? DEFAULT_PERSONA_ID);
}

export function persistPersonaId(id: PersonaId): void {
  if (typeof window !== "undefined") {
    localStorage.setItem(STORAGE_KEY, id);
  }
}

export function getPersona(id: PersonaId): MockPersona {
  return MOCK_PERSONAS.find((p) => p.id === id) ?? MOCK_PERSONAS[2]!;
}

export function getActorId(id: PersonaId): string {
  return getPersona(id).actorId;
}
