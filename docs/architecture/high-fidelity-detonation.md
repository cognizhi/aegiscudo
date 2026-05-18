# High-Fidelity Detonation Worker

High-fidelity detonation is a Phase 3 asynchronous escalation path for suspicious native, JVM, and binary artifacts that need deeper telemetry than the current Emergency Room container profiles can provide. It must never run on the request path and must never receive customer secrets.

## Runtime Decision

Use a hybrid runtime:

- GKE Sandbox/gVisor worker pools for scalable single-use Linux detonation jobs where stronger container isolation and controlled filesystem/network observation are sufficient.
- Dedicated disposable VM workers for cases requiring packet metadata capture, host-side tracing, kernel-adjacent tooling, or malware-style detonation where gVisor visibility is insufficient.
- Kata/Firecracker-style microVMs remain an implementation option when the deployment substrate provides an operationally supported runtime, but Aegiscudo should not assume they are available on every tenant deployment.

This keeps the first production path close to the existing GCP-oriented architecture while preserving an escape hatch for deeper native and packet-level analysis.

Routing guidance:

- Use GKE Sandbox/gVisor for suspicious source-level package execution, JVM class-loading follow-up, and native artifact probes that only need process, filesystem, DNS, and coarse syscall summaries.
- Use disposable VM workers when the profile requires packet metadata, host-side tracing, kernel-adjacent tools, or behavior that gVisor cannot expose reliably.
- Fall back from gVisor to disposable VM only through an explicit escalation job; do not silently rerun artifacts in a more privileged profile.

## Isolation Threat Model

The worker assumes the artifact is adversarial and may attempt sandbox escape, credential theft, time-delay, environment detection, network exfiltration, local persistence, or destructive filesystem behavior.

Required boundaries:

- One artifact per disposable worker instance.
- No customer credentials, registry credentials, cloud admin credentials, or production database access in the worker.
- A per-job identity can read only the selected artifact blob and write only to a narrow telemetry ingestion endpoint and bounded object-storage prefix for reports.
- Egress is denied by default; brokered egress is explicit and recorded.
- Time, CPU, memory, disk, process count, file count, packet metadata volume, and telemetry byte budgets are enforced by the orchestrator and the worker runtime.
- Teardown is mandatory on success, timeout, cancellation, and worker error.

## Lifecycle

1. Emergency Room or Surgeon emits an escalation signal for a suspicious artifact digest.
2. The orchestrator checks tenant high-fidelity quotas and creates a high-fidelity job record.
3. The provisioner creates a single-use GKE Sandbox pod or disposable VM with a per-job identity.
4. The worker downloads the artifact by digest, verifies the digest, plants canaries, and runs the selected profile.
5. The worker captures telemetry and bounded evidence artifacts.
6. The worker uploads telemetry through the ingestion endpoint and marks the job complete, failed, or timed out.
7. The provisioner tears down compute, disk, temporary networking, and per-job identity bindings.
8. A teardown verifier records whether any resource survived cleanup.

If teardown verification fails, the job must be marked with degraded evidence, the substrate must stop accepting new jobs, and an operator alert must be emitted. Retrying teardown is allowed, but successful telemetry ingestion must not hide leaked compute, disk, network, or identity resources.

Current Phase 2 Emergency Room can emit `cargo-native-escalation-pending-hifi` and a `needs_hifi_detonation` flag for suspicious Cargo native artifacts. Those are telemetry-only eligibility signals today; high-fidelity job creation, queueing, quota accounting, and worker provisioning remain future control-plane work.

## Telemetry Model

High-fidelity reports should extend the existing sandbox telemetry shape rather than replace it. Before worker implementation starts, the sandbox telemetry schema needs a versioned high-fidelity report contract with typed per-event fields, field budgets, redaction rules, and compatibility tests for existing evidence readers. Event families:

- `syscall-observed` with syscall name, process identity, result class, and bounded argument summaries.
- `packet-metadata-observed` with timestamp, protocol, source/destination, byte counts, and direction; no payload capture. Any future forensic payload mode requires separate approval, retention policy, redaction design, and tenant-visible audit controls.
- `dns-query-observed` with query name, type, response code, and resolved addresses.
- `process-tree-observed` with parent/child process identity, argv digest, executable path, and exit status.
- `file-access-observed` with path class, operation, process identity, and canary match state.
- `dynamic-library-load-observed` with library path, digest when available, and loading process.
- `jvm-class-load-observed` with class name, jar digest, loader context, and triggering phase when available.
- `native-symbol-observed` and `native-section-observed` for selected binary sections and suspicious symbols.
- `canary-secret-access` and `canary-exfiltration-attempt` reused from Emergency Room.

Telemetry must avoid logging secrets, raw environment dumps, request bodies, auth headers, or full file contents. DNS names, destination hosts, path-like arguments, argv summaries, syscall argument summaries, and file paths can also contain sensitive tenant data; each event family must define truncation, hashing, classification, or allowlisted extraction before implementation.

## Blocked Implementation Gates

- Provisioning requires Terraform/Kubernetes design for worker pools, per-job identity, network policy, object-storage prefixes, and teardown verification.
- High-fidelity telemetry requires a versioned report schema, fixtures, redaction rules, and backwards-compatible evidence-reader behavior before worker code writes events.
- Syscall and packet telemetry require a selected tracing implementation per runtime. gVisor, host eBPF, ptrace/strace, Tracee, tcpdump, or equivalent tooling must be validated against the isolation model before code lands.
- The control plane needs high-fidelity job tables, queue states, tenant quotas, and evidence routes before the worker can persist results.
- Command Center needs a high-fidelity evidence panel before operators can review the deeper telemetry safely.