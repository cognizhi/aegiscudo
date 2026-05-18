import type {
  components as GeneratedAegiscudoApiComponents,
  operations as GeneratedAegiscudoApiOperations,
  paths as GeneratedAegiscudoApiPaths,
} from "./generated/aegiscudo-api.js";

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
  "githubactions",
  "vscode-extension",
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

export type AegiscudoApiComponents = GeneratedAegiscudoApiComponents;
export type AegiscudoApiOperations = GeneratedAegiscudoApiOperations;
export type AegiscudoApiPaths = GeneratedAegiscudoApiPaths;
export type QuarantineQueueItem =
  GeneratedAegiscudoApiComponents["schemas"]["QuarantineQueueItem"];
export type ArtifactEvidence =
  GeneratedAegiscudoApiComponents["schemas"]["ArtifactEvidence"];
export type ArtifactStaticAnalysisReports =
  GeneratedAegiscudoApiComponents["schemas"]["ArtifactStaticAnalysisReports"];
export type ArtifactSandboxExecutionReports =
  GeneratedAegiscudoApiComponents["schemas"]["ArtifactSandboxExecutionReports"];
export type RequestTimelineBucket =
  GeneratedAegiscudoApiComponents["schemas"]["RequestTimelineBucket"];
export type DashboardMetrics =
  GeneratedAegiscudoApiComponents["schemas"]["DashboardMetrics"];
export type PolicyProfileSummary =
  GeneratedAegiscudoApiComponents["schemas"]["PolicyProfileSummary"];
export type PolicySimulationRequest =
  GeneratedAegiscudoApiComponents["schemas"]["PolicySimulationRequest"];
export type PolicyDecisionCounts =
  GeneratedAegiscudoApiComponents["schemas"]["PolicyDecisionCounts"];
export type PolicySimulationResult =
  GeneratedAegiscudoApiComponents["schemas"]["PolicySimulationResult"];
export type OverrideQueueItem =
  GeneratedAegiscudoApiComponents["schemas"]["OverrideQueueItem"];
export type OverrideActionRequest =
  GeneratedAegiscudoApiComponents["schemas"]["OverrideActionRequest"];
export type OverrideResponse =
  GeneratedAegiscudoApiComponents["schemas"]["OverrideResponse"];
export type InvestigationAuditEvent =
  GeneratedAegiscudoApiComponents["schemas"]["AuditEvent"];
export type AuthMode = GeneratedAegiscudoApiComponents["schemas"]["AuthMode"];
export type AuthSubject = GeneratedAegiscudoApiComponents["schemas"]["AuthSubject"];
export type AuthSession = GeneratedAegiscudoApiComponents["schemas"]["AuthSession"];
export type MockIdentityList =
  GeneratedAegiscudoApiComponents["schemas"]["MockIdentityList"];
export type SetMockAuthSessionRequest =
  GeneratedAegiscudoApiComponents["schemas"]["SetMockAuthSessionRequest"];
export type RegistryConfig =
  GeneratedAegiscudoApiComponents["schemas"]["RegistryConfig"];
export type CreateRegistryConfigRequest =
  GeneratedAegiscudoApiComponents["schemas"]["CreateRegistryConfigRequest"];
export type UpdateRegistryConfigRequest =
  GeneratedAegiscudoApiComponents["schemas"]["UpdateRegistryConfigRequest"];
export type CredentialStatus =
  GeneratedAegiscudoApiComponents["schemas"]["CredentialStatus"];
export type CreateCredentialRequest =
  GeneratedAegiscudoApiComponents["schemas"]["CreateCredentialRequest"];
export type ConnectionTestResult =
  GeneratedAegiscudoApiComponents["schemas"]["ConnectionTestResult"];
export type AiProviderConfig =
  GeneratedAegiscudoApiComponents["schemas"]["AiProviderConfig"];
export type LlmUsage =
  GeneratedAegiscudoApiComponents["schemas"]["LlmUsage"];
export type LlmUsageSummary =
  GeneratedAegiscudoApiComponents["schemas"]["LlmUsageSummary"];
export type LlmUsageProviderModel =
  GeneratedAegiscudoApiComponents["schemas"]["LlmUsageProviderModel"];
export type LlmUsageAnalysisJob =
  GeneratedAegiscudoApiComponents["schemas"]["LlmUsageAnalysisJob"];
export type LlmUsageFailingTrace =
  GeneratedAegiscudoApiComponents["schemas"]["LlmUsageFailingTrace"];
export type LlmUsagePromptTemplateVersion =
  GeneratedAegiscudoApiComponents["schemas"]["LlmUsagePromptTemplateVersion"];
export type SbomNtiaValidation =
  GeneratedAegiscudoApiComponents["schemas"]["SbomNtiaValidation"];
export type SbomDocumentSummary =
  GeneratedAegiscudoApiComponents["schemas"]["SbomDocumentSummary"];
export type OpenVexExpiryPolicy =
  GeneratedAegiscudoApiComponents["schemas"]["OpenVexExpiryPolicy"];
export type OpenVexDocumentSummary =
  GeneratedAegiscudoApiComponents["schemas"]["OpenVexDocumentSummary"];
export type OpenVexDocument =
  GeneratedAegiscudoApiComponents["schemas"]["OpenVexDocument"];
export type SignalPolicyAction =
  GeneratedAegiscudoApiComponents["schemas"]["SignalPolicyAction"];
export type ScorecardCheckThreshold =
  GeneratedAegiscudoApiComponents["schemas"]["ScorecardCheckThreshold"];
export type PolicyScorecardThresholds =
  GeneratedAegiscudoApiComponents["schemas"]["PolicyScorecardThresholds"];
export type DepsDdevPackageSummary =
  GeneratedAegiscudoApiComponents["schemas"]["DepsDdevPackageSummary"];
export type DepsDdevPackagesResponse =
  GeneratedAegiscudoApiComponents["schemas"]["DepsDdevPackagesResponse"];
export type IocRecordSummary =
  GeneratedAegiscudoApiComponents["schemas"]["IocRecordSummary"];
export type IocRecordsResponse =
  GeneratedAegiscudoApiComponents["schemas"]["IocRecordsResponse"];
export type GithubActionsScanResult =
  GeneratedAegiscudoApiComponents["schemas"]["GithubActionsScanResult"];

export function purl(coordinate: PackageCoordinate): string {
  const packagePath = coordinate.namespace
    ? `${coordinate.namespace}/${coordinate.name}`
    : coordinate.name;
  return coordinate.version
    ? `pkg:${coordinate.ecosystem}/${packagePath}@${coordinate.version}`
    : `pkg:${coordinate.ecosystem}/${packagePath}`;
}