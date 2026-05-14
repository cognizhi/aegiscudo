# Reachability Analysis Design: JavaScript and TypeScript

Source PRD sections: §3.6, §4.4, §4.5 (Phase 2 deep analysis); Phase 2 plan §Policy Evolution.

This document defines the design assumptions, scope boundaries, and implementation approach
for reachability analysis of JavaScript and TypeScript packages. Reachability analysis must
be validated against ecosystem-specific call graph assumptions before implementation begins,
per the Phase 2 plan mandate.

## Goal

Reduce false positives in vulnerability scoring by distinguishing between:

- **Reachable vulnerabilities**: a vulnerable code path exists and is transitively callable
  from the root package's main entry points (including `exports`, `main`, `bin` entries,
  and tree-shaken module boundaries).
- **Unreachable vulnerabilities**: a vulnerable function exists in a transitive dependency
  but cannot be reached given the observed call graph from the root package.

## Scope and Non-Goals

**In scope for design validation:**
- npm packages (CommonJS and ESM) with `package.json` entry points.
- TypeScript packages that are transpiled before distribution (`.d.ts` + `.js` in
  `dist/` or `lib/`; source `.ts` not assumed to be present in artifacts).
- Packages published to npm with `exports` field (subpath exports and conditional exports).

**Out of scope:**
- Deno packages.
- Bun-specific module loading extensions.
- Runtime-dynamic `require()` calls (string expressions computed at runtime).
- Webpack/Rollup/esbuild bundled artifacts where the module graph has been collapsed.
- Packages whose source is obfuscated or minified without source maps.

## Prerequisites and Validation Gates

Reachability implementation is gated on validating the following assumptions against real
npm packages and internal test fixtures before any production code is written.

### Assumption 1: Static call graph approximation is sound for a useful fraction of packages

Dynamic dispatch, `eval`, `Function()`, and dynamic `require()` break static call graphs.
A static analysis tool over npm packages must be validated to determine what fraction of
package surface area can be approximated soundly.

**Validation method**: Run a static call graph tool (see tooling candidates below) over
the top-100 npm packages by download count. Measure what percentage of `exports` entry
points produce non-empty call graphs and what percentage contain at least one reachable
path to a known CVE function.

**Acceptance threshold**: If fewer than 40% of packages in the validation set produce
non-trivial call graphs, static reachability is not reliable enough to gate policy
decisions. In that case, reachability should be surfaced only as an advisory signal with
no block authority.

### Assumption 2: Entry point discovery from `package.json` is consistent

npm packages expose entry points via `main`, `exports`, `module`, and `bin` fields.
The `exports` field supports conditional resolution (`import`, `require`, `default`) and
subpath patterns (`./utils/*`). Call graph construction must start from a consistent
set of entry points.

**Validation method**: Inspect the top-100 npm packages. Record what percentage use
`exports` maps, what percentage have only `main`, and what percentage use `bin` as an
analysis entry point.

**Acceptance threshold**: If more than 20% of packages lack a stable entry point
discoverable without runtime resolution, entry point heuristics must be documented and
reviewed before enabling reachability gating.

### Assumption 3: Transitive vulnerability-to-function mapping is available

Call graph reachability is only useful when the vulnerable function in the dependency can
be identified by name or code location. OSV advisories carry `affected.ranges` and
`affected.ecosystem_specific` fields, but function-level granularity varies by advisory.

**Validation method**: Sample 50 npm CVEs from OSV and check what fraction carry
function-level identifiers (`affected.ecosystem_specific.functions` or equivalent).

**Acceptance threshold**: If fewer than 30% of sampled advisories carry function-level
identifiers, reachability is limited to module-level granularity only.

## Tooling Candidates

### Option A: `@npmcli/arborist` + custom call graph walker

- Use `@npmcli/arborist` to resolve the dependency tree from `package-lock.json`.
- Walk `exports` and `main` entry points in the root package.
- Use a lightweight static import/require tracer (Node.js `acorn` or `@babel/parser` AST)
  to follow `require()`/`import` edges transitively.
- No external dependencies outside the Node.js ecosystem.

**Pros**: No new language runtime required in Surgeon or Emergency Room; fits npm analysis
flow already implemented.

**Cons**: Hand-written call graph walker is limited to static imports. Does not handle
dynamic dispatch or conditional module loading.

### Option B: `esm-dependency-graph` or `dependency-cruiser`

- `dependency-cruiser` statically resolves `import`/`require` edges across a directory
  tree and outputs a graph in JSON, DOT, or Mermaid.
- Can run without a full compile step against `.js` or `.ts` source.
- Configurable resolution rules matching npm/TypeScript path aliases.

**Pros**: Maintained tooling with TypeScript-aware resolution.

**Cons**: Module-graph level only (not function-level). Requires Node.js runtime in the
Surgeon analysis container.

### Option C: CodeQL JavaScript/TypeScript analysis

- CodeQL provides data-flow and call graph analysis for JS/TS.
- Can identify tainted data paths from entry points to known vulnerable sinks.
- GH Actions workflows already scanned via CodeQL in separate integrations.

**Pros**: Industry-standard, function-level granularity, precise data flow.

**Cons**: Requires CodeQL CLI and a CodeQL database build. License requires GitHub
subscription for private code. Build time for large packages may exceed sandbox limits.
Only appropriate for asynchronous analysis in Emergency Room, not Surgeon static path.

### Option D: `semgrep` with JS/TS rules

- `semgrep` with curated JS/TS ruleset can detect calls to vulnerable patterns.
- Pattern-based, not call-graph-based. Identifies vulnerable code patterns regardless
  of whether they are reachable.
- Already considered for general static analysis in Surgeon.

**Cons**: Not reachability analysis; does not distinguish reachable from unreachable
vulnerabilities. Keeps as a complementary signal.

## Recommended Approach (Post-Validation)

If validation gates pass:

1. **Module-level reachability** (Option B, `dependency-cruiser`): Run in Surgeon static
   analysis path. Produces a module dependency graph. Marks a vulnerability as potentially
   reachable if the vulnerable module is transitively imported from a root entry point.
   Low precision but fast and license-permissive.

2. **Function-level reachability** (Option C, CodeQL, async Emergency Room only):
   For packages that trigger a Triage Counter `QUARANTINE_PENDING_ANALYSIS` or
   `REQUIRE_HITL_APPROVAL` verdict, schedule an Emergency Room detonation with CodeQL
   analysis. Emit function-level reachability evidence into the analysis job record.
   Triage Counter can then downgrade a `BLOCK_POLICY_VIOLATION` to `ALLOW_WITH_WARNING`
   when CodeQL confirms no reachable path to the vulnerable function, subject to policy
   profile configuration.

## Evidence Contract

A new `ReachabilityEvidence` struct should be added to `schemas/evidence.schema.json` and
the corresponding Rust DTOs in `crates/aegiscudo-protocol`. Fields:

```json
{
  "ecosystem": "npm",
  "package_name": "example",
  "package_version": "1.0.0",
  "analysis_method": "module-graph | call-graph-static | call-graph-codeql",
  "entry_points_analyzed": ["dist/index.js", "bin/cli.js"],
  "reachable_modules": ["node_modules/vulnerable-dep/index.js"],
  "unreachable_modules": [],
  "reachable_functions": [],
  "confidence": "low | medium | high",
  "advisory_ids": ["GHSA-xxxx-xxxx-xxxx"],
  "notes": ""
}
```

Confidence is `low` for module-graph analysis, `medium` for static call graph, and `high`
for CodeQL data-flow analysis.

## Policy Integration

Once evidence is available, Triage Counter can integrate reachability as follows:

- A `reachability_threshold` optional field in `PolicyProfile.vulnerability_thresholds` can
  gate whether an unreachable-confirmed finding downgrades from BLOCK to ALLOW_WITH_WARNING.
- VEX `not_affected` status with `vulnerable_code_not_in_execute_path` justification aligns
  with module-level unreachability evidence and should be correlated when both are present.
- Reachability evidence must never be the sole reason to suppress a BLOCK decision without
  an explicit policy profile opt-in and an audit event.

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Dynamic `require()` bypasses static graph | Document as known limitation; confidence = low |
| Bundled/minified packages lack module boundaries | Detect minification and fall back to no-reachability advisory |
| CodeQL license constraints | Use only for packages already queued for sandbox analysis |
| Advisory function names not in OSV | Harvest function identifiers from NVD, GHSA, and curated supplement |
| Reachability false negatives allow malicious packages | Reachability is never the sole allow signal; BLOCK requires explicit opt-out |

## Implementation Order

1. Write and run validation scripts against top-100 npm packages (not in Surgeon; separate
   tooling script under `scripts/`).
2. If validation gates pass, add `dependency-cruiser` to the Surgeon npm analysis flow.
3. Add `ReachabilityEvidence` to `schemas/evidence.schema.json`.
4. Wire module-level reachability into Triage Counter as an advisory signal.
5. Evaluate CodeQL Emergency Room path in Phase 3.
