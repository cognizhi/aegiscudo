export const policyDecisions = [
  "ALLOW",
  "ALLOW_WITH_WARNING",
  "QUARANTINE_PENDING_ANALYSIS",
  "BLOCK_KNOWN_MALICIOUS",
  "BLOCK_POLICY_VIOLATION",
  "REQUIRE_HITL_APPROVAL",
  "FALLBACK_TO_APPROVED_CANDIDATE",
] as const;

export type PolicyDecision = (typeof policyDecisions)[number];

export const packageEcosystems = [
  "npm",
  "pypi",
  "cargo",
  "maven",
  "docker-oci",
  "generic-http",
] as const;

export type PackageEcosystem = (typeof packageEcosystems)[number];

export interface PackageCoordinate {
  ecosystem: PackageEcosystem;
  name: string;
  version?: string;
  namespace?: string;
}

export interface DecisionSummary {
  coordinate: PackageCoordinate;
  decision: PolicyDecision;
  traceId: string;
  rationale: string[];
}

export type {
  components as AegiscudoApiComponents,
  operations as AegiscudoApiOperations,
  paths as AegiscudoApiPaths,
} from "./generated/aegiscudo-api.js";

export function purl(coordinate: PackageCoordinate): string {
  const packagePath = coordinate.namespace
    ? `${coordinate.namespace}/${coordinate.name}`
    : coordinate.name;
  return coordinate.version
    ? `pkg:${coordinate.ecosystem}/${packagePath}@${coordinate.version}`
    : `pkg:${coordinate.ecosystem}/${packagePath}`;
}