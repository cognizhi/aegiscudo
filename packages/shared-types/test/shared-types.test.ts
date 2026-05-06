import type {
  AegiscudoApiComponents,
  AegiscudoApiOperations,
  AegiscudoApiPaths,
} from "../src/index";
import { describe, expect, it } from "vitest";

import { purl, policyDecisions } from "../src/index";

describe("shared types", () => {
  it("keeps PRD decision names intact", () => {
    expect(policyDecisions).toContain("REQUIRE_HITL_APPROVAL");
  });

  it("formats package URLs", () => {
    expect(purl({ ecosystem: "npm", namespace: "scope", name: "pkg", version: "1.0.0" })).toBe(
      "pkg:npm/scope/pkg@1.0.0",
    );
  });

  it("exports generated OpenAPI contract aliases", () => {
    type OpenApiContractAliases = [
      AegiscudoApiPaths,
      AegiscudoApiOperations,
      AegiscudoApiComponents,
    ];

    const smoke: OpenApiContractAliases | null = null;

    expect(smoke).toBeNull();
  });
});