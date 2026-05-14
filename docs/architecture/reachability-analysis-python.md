# Reachability Analysis Design: Python

Source PRD sections: §3.6, §4.4, §4.5 (Phase 2 deep analysis); Phase 2 plan §Policy Evolution.

This document defines the design assumptions, scope boundaries, and implementation approach
for reachability analysis of Python packages. Reachability analysis must be validated against
ecosystem-specific call graph assumptions before implementation begins, per the Phase 2 plan.

## Goal

Reduce false positives in vulnerability scoring by distinguishing between:

- **Reachable vulnerabilities**: a vulnerable code path exists and is transitively callable
  from the root package's public module surface (`__init__.py`, entry points, console scripts).
- **Unreachable vulnerabilities**: a vulnerable function exists in a transitive dependency
  but cannot be reached under any realistic import chain from the root package.

## Scope and Non-Goals

**In scope for design validation:**
- PyPI wheel (`.whl`) and source distribution (`.tar.gz`) packages.
- Packages using standard Python import semantics (not namespace packages with custom finders).
- Packages that declare `[project.scripts]` / `[project.entry-points]` in `pyproject.toml`
  or `entry_points` in `setup.cfg`.
- Python 3.9+ syntax assumptions (no Python 2 legacy `imp` module analysis).

**Out of scope:**
- Packages that use `ctypes.CDLL`, `cffi`, or extension modules for runtime behavior.
  Native call paths cannot be analyzed statically without decompiling the extension.
- Packages with `__import__`, `importlib.import_module`, or `importlib.util.spec_from_file_location`
  calls where the module name is a runtime-computed string.
- Conda packages and `conda-forge` distributions.
- Jupyter kernel packages where execution context varies by notebook.

## Prerequisites and Validation Gates

### Assumption 1: Static import graph approximation covers a useful fraction of packages

Python's import system is highly dynamic. `__all__`, conditional imports inside `if TYPE_CHECKING:`,
deferred imports inside functions, and plugin-style `entry_points` all affect whether a module
is reachable under static analysis.

**Validation method**: Run a static import graph tool (see candidates below) over the top-50
PyPI packages by monthly download count (using PyPI stats API). Measure:
- What percentage produce a non-empty static import graph.
- What percentage have at least one reachable path to a function in a known vulnerable module.

**Acceptance threshold**: If fewer than 35% of validation set packages produce a non-trivial
import graph, static reachability should be advisory-only with no block authority.

### Assumption 2: Vulnerable function names are available in OSV/PyPI advisory data

PyPI/OSV advisories sometimes carry `affected.ecosystem_specific.imports` or
`affected.ranges` with introduced/fixed versions, but rarely function-level identifiers.

**Validation method**: Sample 50 recent PyPI CVEs from OSV and PyPI Advisory Database.
Check what fraction carry module-level or function-level identifiers.

**Acceptance threshold**: If fewer than 25% of sampled advisories carry module-level
identifiers, reachability analysis must fall back to package-level granularity only
(i.e., "is the vulnerable package imported at all").

### Assumption 3: Entry point discovery from distribution metadata is stable

PyPI packages expose entry points via `[project.scripts]` in `pyproject.toml`,
`[options.entry_points]` in `setup.cfg`, or `entry_points` in `setup.py`. Wheel METADATA
records these in `RECORD` and `entry_points.txt`. For installed packages, they are resolvable
via `importlib.metadata.entry_points()`.

**Validation method**: Parse `entry_points.txt` or `pyproject.toml` from a sample of 50
PyPI wheel files. Record what percentage have at least one resolvable entry point or
`__init__.py` as a fallback.

**Acceptance threshold**: If more than 20% of packages lack any entry point and have no
`__init__.py` at the package root, entry point discovery must fall back to the full
`sys.path`-resolved module surface.

## Tooling Candidates

### Option A: `pydeps` with call graph mode

- `pydeps` produces module-level dependency graphs from installed packages by tracing imports.
- Outputs DOT or JSON. Can be run against a sandboxed Python environment.
- Requires actually installing the package (not pure static analysis from the wheel file).

**Pros**: Accurate module import graph via import tracing.

**Cons**: Requires package installation (introduces import-time execution risk). Must run
inside an isolated Emergency Room environment, not in Surgeon static path.

### Option B: `importlab` (Google)

- `importlab` resolves Python import graphs by statically parsing AST `import` statements.
- Works on source files without execution. Handles relative imports and `__init__.py`.
- Used by `pytype` for type inference.

**Pros**: Pure static analysis, no execution required. Can run in Surgeon.

**Cons**: Less accurate for dynamic imports. Requires source files — wheel `.pyc`-only
distributions may not expose readable source.

### Option C: `pyan3` (Python call graph analyzer)

- `pyan3` performs static call graph analysis from Python source, identifying function-level
  definitions and call edges.
- Outputs DOT, JSON, or YAML call graphs.

**Pros**: Function-level granularity, static analysis.

**Cons**: Requires Python source in the wheel/sdist. Does not handle `__getattr__`-based
attribute dispatch. Accuracy degrades on heavily metaprogrammed code.

### Option D: `astroid` / `pylint` call graph

- `astroid` is the Pylint AST framework with name inference, type inference, and import
  resolution capabilities.
- Can be used to build a function-level call graph by walking `Call` nodes in the AST and
  resolving callees via `astroid`'s inference engine.

**Pros**: Handles relative imports, `__all__`, and some dynamic attribute resolution.

**Cons**: Significant setup complexity for non-installed packages. Inference failures are
common for packages with complex metaclasses or dynamic attribute access.

### Option E: Bandit + importlib-based surface scan (simplest viable path)

- Run `bandit` over the extracted package source during Surgeon static analysis.
- Separately, parse `import` statements in the package's `__init__.py` and public modules
  using `ast.parse` to produce a module-level import surface.
- Match CVE-affected module names against the import surface.

**Pros**: Zero new runtime dependencies. Module-level reachability from pure AST parsing
without a call graph. Fast.

**Cons**: Module-level only (not function-level). May miss lazy imports inside function bodies.

## Recommended Approach (Post-Validation)

If validation gates pass:

1. **Module-level reachability** (Option E, AST-based, in Surgeon): Parse `import` and
   `from ... import` statements in the package's public module surface (`__init__.py`,
   `__main__.py`, console script entry points). Build the reachable module set transitively
   within the package source tree. Compare against CVE-affected module names from OSV.
   Emit `ReachabilityEvidence` with `confidence = low`.

2. **Function-level reachability** (Option C, `pyan3`, async Emergency Room only): For
   packages queued for sandbox analysis, run `pyan3` over the full extracted source tree.
   Match CVE-affected function names against the call graph reachable from the entry points.
   Emit `ReachabilityEvidence` with `confidence = medium`.

3. **Execution-time import trace** (Option A, `pydeps`, Emergency Room sandbox only): Run
   inside the PyPI sandbox profile (phase D, install; phase G, import test). Capture the
   import trace and compare it against CVE-affected modules. Emit `ReachabilityEvidence` with
   `confidence = high` only when the import trace and static graph agree.

## Evidence Contract

A new `ReachabilityEvidence` struct shared with the JavaScript design (see
`docs/architecture/reachability-analysis-javascript.md`) should cover both ecosystems:

```json
{
  "ecosystem": "pypi",
  "package_name": "example",
  "package_version": "1.0.0",
  "analysis_method": "module-graph | call-graph-static | call-graph-runtime",
  "entry_points_analyzed": ["example/__init__.py", "example/__main__.py"],
  "reachable_modules": ["vulnerable_dep.dangerous_module"],
  "unreachable_modules": [],
  "reachable_functions": [],
  "confidence": "low | medium | high",
  "advisory_ids": ["PYSEC-XXXX-XXXX"],
  "notes": ""
}
```

Confidence levels mirror the JavaScript design for consistency:
- `low` = module-graph AST scan (Option E)
- `medium` = function-level static call graph (Option C)
- `high` = execution-time import trace corroborated by static graph

## Policy Integration

Once evidence is available, Triage Counter integration mirrors the JavaScript design:

- A `reachability_threshold` optional field in `PolicyProfile.vulnerability_thresholds`
  can gate whether an unreachable-confirmed finding downgrades from BLOCK to ALLOW_WITH_WARNING.
- VEX `not_affected` with `vulnerable_code_not_in_execute_path` justification should be
  correlated against module-level unreachability evidence when both are present.
- Reachability evidence must never be the sole reason to suppress a BLOCK decision without
  an explicit policy profile opt-in and an audit event.

## Python-Specific Risk Surface

Python's import side effects make reachability analysis higher-stakes than for JavaScript:

- `__init__.py` runs at import time. Code in package init modules is always executed when
  the package is imported, regardless of which submodule is used.
- Decorator factories and metaclasses run at class-definition time. A vulnerable function
  may be called during module initialization even if the function itself is never called
  from application code.
- `atexit` handlers and `sys.excepthook` registrations persist for the process lifetime.

These patterns mean **module-level import reachability is a stronger signal in Python than
in JavaScript**, because importing a Python module is more likely to execute side-effecting
code than importing a JavaScript module. The advisory-signal value of module-level analysis
is correspondingly higher for PyPI than for npm.

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Dynamic imports via `importlib` bypass static graph | Document as known gap; confidence = low |
| `.pyc`-only wheels lack readable source | Fall back to no-reachability advisory; flag pyc-only distribution |
| `__init__.py` side effects at import time | Module-level reachability = strong signal regardless of function calls |
| Advisory function identifiers missing from OSV | Harvest from PyPI Advisory Database, NVD, and curated supplement |
| AST parse fails for syntax-3.12+ features | Pin `ast` parsing to detected Python version of the package |
| Reachability false negatives allow malicious packages | Reachability is never the sole allow signal |

## Implementation Order

1. Write and run validation scripts against the top-50 PyPI packages (separate tooling
   script under `scripts/`).
2. If validation gates pass, add AST-based module-level reachability to Surgeon PyPI analysis.
3. Add `ReachabilityEvidence` to `schemas/evidence.schema.json` (shared with JS design).
4. Wire module-level reachability into Triage Counter as an advisory signal.
5. Evaluate `pyan3` Emergency Room path in Phase 3.
