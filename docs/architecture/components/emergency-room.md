# Emergency Room

Source PRD sections: Feature 4, 3.3, 3.7.2, 4.4, 4.6.

Emergency Room is the sandbox orchestration component for dynamic package behavior analysis.

## Responsibilities

- Select sandbox profiles for npm, PyPI, Cargo, and Maven analysis jobs.
- Launch isolated executions with no customer secrets, no privileged mode, and no host mounts.
- Plant canary credentials and AI-agent configuration files.
- Capture process, filesystem, network, canary, stdout/stderr, timeout, and exit-code telemetry.
- Attribute behavior to root package, lifecycle phase, dependency, build tool, or import probe where practical.
- Persist telemetry with analysis job and artifact references.

## Sandbox Boundary

Sandboxes must be single-use execution environments with strict CPU, memory, egress, and timeout controls. They may write telemetry only to a narrow append-only ingestion endpoint and must not have write access to production databases.

## Current Implementation State

The Python service now runs local npm, PyPI, Cargo, and Maven/JVM sandbox profiles with canary planting, timeout handling, stdout/stderr redaction, structured telemetry emission, and focused integration coverage. The Maven path currently provides an initial `jvm-binary-profile`: it selects classes from packaged `.jar` / `.war` / `.ear` artifacts, uses a temporary Java source probe plus `Class.forName(..., true, ...)` to trigger class loading and static initializers in-process, and emits `jvm-class-loaded` telemetry for selected artifact classes confirmed in `java -verbose:class` output. It also relies on the existing exfiltration collector plus canary environment to capture network and secret-access signals. `outbound-network-attempt` telemetry now carries normalized `destination_url`, `destination_host`, and `destination_ip` fields so downstream policy evaluation can correlate sandbox egress against feed-harvested cross-ecosystem IOC records. Broader JVM runtime attribution, generalized filesystem/process tracing, containerized Cloud Run Jobs orchestration, and production sandbox deployment hardening remain later-phase work.