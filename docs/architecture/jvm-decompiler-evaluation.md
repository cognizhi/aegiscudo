# JVM Decompiler Evaluation

Source PRD sections: [4.4 Static Analysis](../prd/aegiescudo-prd.md), [4.6 High-Fidelity Detonation Worker](../prd/aegiescudo-prd.md), and Phase 2 plan Maven/JVM expansion rows.

## Scope

This document evaluates optional Java decompilation tooling for asynchronous JVM artifact analysis. The goal is not to make decompilation a request-time requirement. Any decompiler integration must remain:

- asynchronous only
- advisory only
- offline or operator-controlled
- inside the existing Aegiscudo trust boundary

The immediate question is which tool is the best fit if Surgeon or a later high-fidelity JVM worker needs to decompile selected classes for analyst context.

## Evaluation Criteria

The Phase 2 choice must satisfy both technical and governance constraints:

- license must allow internal distribution and operational packaging without custom approval
- headless CLI automation must be practical for batch analysis jobs
- setup footprint must be reasonable for local development and CI
- output quality must be useful on modern Java bytecode, not only legacy class files
- tool behavior on malformed or adversarial bytecode must fail safely enough for an offline analysis pipeline
- the integration must not force Aegiscudo to widen the request-time trust boundary

## CFR

Current upstream facts used for this evaluation:

- upstream project: [CFR](https://www.benf.org/other/cfr/)
- license: MIT
- operational model: standalone JAR CLI
- current upstream note: public site still lists `0.152` as the latest published jar, while the maintainer notes renewed work in March 2026 and points operators to the GitHub repo for newer source

Fit for Aegiscudo:

- strongest headless fit of the three tools for a narrow batch decompilation step
- low operational overhead because it runs as a single Java process without a heavyweight framework runtime
- good match for asynchronous worker invocation against selected classes or jars
- modern Java language support is explicitly a project focus, which matters for current Maven ecosystems

Risks:

- public release cadence is irregular, so packaging should pin an internally reviewed version instead of following latest-by-default
- output quality can still vary on heavily obfuscated or malformed bytecode, so results must stay advisory

Phase 2 conclusion:

- CFR is the preferred default if Aegiscudo adds optional local JVM decompilation in the analysis plane

## Fernflower

Current upstream facts used for this evaluation:

- upstream project: JetBrains Fernflower in IntelliJ Community
- license: Apache License 2.0
- operational model: standalone CLI JAR plus IntelliJ integration
- maintainer posture: actively maintained as part of IntelliJ Community, with CLI options intended for decompiler and reverse-engineering use

Fit for Aegiscudo:

- license is operationally easy
- headless CLI use is viable
- maintenance posture is stronger and more predictable than CFR's public release cadence
- good secondary baseline when Aegiscudo wants a second opinion on decompiled readability or syntax reconstruction

Risks:

- it is primarily maintained for IDE readability and navigation, not as a malware-analysis-first pipeline component
- compared with CFR, it is a weaker primary choice for adversarial supply-chain triage where malformed or obfuscated bytecode is expected more often

Phase 2 conclusion:

- Fernflower is a reasonable secondary or fallback decompiler, but not the first tool to embed in the default offline analysis path

## Ghidra

Current upstream facts used for this evaluation:

- upstream project: NSA Ghidra SRE framework
- license: Apache License 2.0
- operational model: full software reverse-engineering framework with decompilation, disassembly, graphing, scripting, and extension support
- operational warning: upstream README explicitly calls out current security advisories and a significantly heavier install and build footprint

Fit for Aegiscudo:

- highest ceiling for deep reverse engineering and analyst-driven escalation
- strong match for later high-fidelity detonation or manual escalation workflows
- useful when bytecode decompilation must be combined with deeper binary or interactive reverse-engineering analysis

Risks:

- too heavy for the default Phase 2 offline decompilation path
- larger runtime and build footprint than Surgeon should absorb for routine class inspection
- the upstream security-advisory warning raises the bar for version pinning and operational maintenance
- best value comes from a richer analyst workflow than Aegiscudo currently exposes in Phase 2

Phase 2 conclusion:

- Ghidra should be reserved for future high-fidelity escalation, not the default decompiler embedded into Surgeon

## Phase 2 Decision

If Aegiscudo adds optional local JVM decompilation during Phase 2 or early Phase 3:

1. Prefer CFR as the default headless decompiler.
2. Keep Fernflower as a secondary comparison candidate or fallback when readability is better on a given class set.
3. Reserve Ghidra for high-fidelity escalation workflows rather than the standard asynchronous scan path.

## Operating Rules

- Decompilation must stay out of request-time services.
- Decompiled output is analyst context, not a sole enforcement authority.
- Pin reviewed tool versions explicitly; do not fetch latest releases dynamically.
- Run decompilers only against locally stored artifacts inside bounded temporary work directories.
- Treat decompiler output as adversarial input for any downstream summarization or UI rendering.

## Resulting Recommendation

Phase 2 should standardize on CFR as the first optional JVM decompiler to evaluate for automation, keep Fernflower as the most practical fallback comparator, and defer Ghidra to a later high-fidelity analysis worker where its heavier footprint and broader SRE feature set are justified.