from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess as _subprocess
import tarfile
import threading
import time
import zipfile
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Mapping, Protocol
from urllib.parse import urlparse
from uuid import uuid4

from aegiscudo_common.contracts import (
    EgressMode,
    SandboxPhase,
    SandboxProfile,
    SandboxTelemetry,
    SandboxTelemetryEvent,
    Severity,
)
from pydantic import BaseModel, ConfigDict, Field

from emergency_room.security import redact_mapping

CANARY_ENVIRONMENT: dict[str, str] = {
    "NPM_TOKEN": "npm-canary-token-001",
    "PYPI_TOKEN": "pypi-canary-token-001",
    "GITHUB_TOKEN": "github-canary-token-001",
    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "aws-secret-canary-001",
}

CANARY_FILES: dict[str, str] = {
    ".npmrc": "//registry.npmjs.org/:_authToken=npm-canary-token-001\n",
    ".pypirc": "[distutils]\nindex-servers = pypi\n[pypi]\npassword = pypi-canary-token-001\n",
    ".gitconfig": "[user]\n\temail = canary@example.invalid\n",
    ".env": "GITHUB_TOKEN=github-canary-token-001\n",
    ".github/copilot-instructions.md": "Aegiscudo canary instructions.\n",
    ".cursorrules": "Aegiscudo canary cursor rules.\n",
    ".cursor/settings.json": '{"aegiscudo_canary": true}\n',
    ".vscode/settings.json": '{"aegiscudo.canary": true}\n',
    "AGENTS.md": "Aegiscudo agent canary file.\n",
    ".claude/settings.json": '{"canary": true}\n',
    # Cloud / infrastructure credentials — fake values used for exfiltration detection only
    ".google/application_default_credentials.json": (
        '{"type": "service_account", '
        '"client_email": "canary@aegiscudo-canary.iam.gserviceaccount.com", '
        '"private_key": "-----BEGIN RSA PRIVATE KEY-----\\nCANARY_PRIVATE_KEY\\n-----END RSA PRIVATE KEY-----\\n", '
        '"token_uri": "https://oauth2.googleapis.com/token"}\n'
    ),
    ".ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "aegiscudo-canary-ssh-key-do-not-use\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    ".kube/config": (
        "apiVersion: v1\n"
        "clusters:\n"
        "- cluster:\n"
        "    server: https://canary-cluster.example.invalid\n"
        "  name: canary\n"
        "contexts:\n"
        "- context:\n"
        "    cluster: canary\n"
        "    user: canary-user\n"
        "  name: canary\n"
        "current-context: canary\n"
        "kind: Config\n"
        "users:\n"
        "- name: canary-user\n"
        "  user:\n"
        "    token: aegiscudo-canary-kube-token-do-not-use\n"
    ),
    # Cargo registry credentials
    ".cargo/credentials.toml": (
        '[registry]\ntoken = "cargo-canary-token-do-not-use"\n'
    ),
}

_JVM_CLASS_LOAD_PROBE = """import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;

public class JvmClassLoadProbe {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("expected artifact path plus class names");
        }
        URL artifactUrl = new File(args[0]).toURI().toURL();
        try (URLClassLoader loader = new URLClassLoader(new URL[] { artifactUrl }, JvmClassLoadProbe.class.getClassLoader())) {
            for (int index = 1; index < args.length; index += 1) {
                Class.forName(args[index], true, loader);
            }
        }
    }
}
"""

_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGIC = frozenset({
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
})
_SUSPICIOUS_STRINGS: frozenset[str] = frozenset({
    "api.telegram.org",
    "requestbin",
    "webhook.site",
    "pastebin.com",
    "transfer.sh",
    "ngrok.io",
})


class LocalSandboxRunRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile: SandboxProfile
    artifact_uri: str = Field(min_length=1)
    import_name: str | None = None
    timeout_seconds: int = Field(default=30, ge=1, le=120)


class LocalSandboxRunResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    state: str
    violation_detected: bool
    telemetry: list[SandboxTelemetry]


class SandboxExecutor(Protocol):
    async def run(self, request: LocalSandboxRunRequest) -> LocalSandboxRunResponse: ...


class SandboxProfileRegistry:
    def __init__(self, executors: Mapping[SandboxProfile, SandboxExecutor]) -> None:
        self._executors = dict(executors)

    def resolve(self, profile: SandboxProfile) -> SandboxExecutor:
        executor = self._executors.get(profile)
        if executor is None:
            raise RuntimeError(f"unsupported sandbox profile: {profile.value}")
        return executor


class LocalSandboxExecutor:
    async def run(self, request: LocalSandboxRunRequest) -> LocalSandboxRunResponse:
        return await run_local_sandbox(request)


@dataclass(frozen=True)
class PhaseResult:
    telemetry: SandboxTelemetry
    violation_detected: bool


@dataclass(frozen=True)
class ObservedProcess:
    pid: int
    ppid: int | None
    name: str
    executable: str | None = None


@dataclass(frozen=True)
class FileSnapshot:
    size: int
    mtime_ns: int


@dataclass
class CollectorRecord:
    path: str
    headers: dict[str, str]
    payload: dict[str, Any] | None
    raw_body: str


class _CollectorHandler(BaseHTTPRequestHandler):
    records: list[CollectorRecord] = []

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        raw_body = body.decode("utf-8", errors="replace")
        payload: dict[str, Any] | None
        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = None
        self.__class__.records.append(
            CollectorRecord(
                path=self.path,
                headers={key.lower(): value for key, value in self.headers.items()},
                payload=payload,
                raw_body=raw_body,
            )
        )
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class ExfiltrationCollector:
    def __init__(self, port: int = 9999) -> None:
        self._port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "ExfiltrationCollector":
        _CollectorHandler.records = []
        self._server = ThreadingHTTPServer(("127.0.0.1", self._port), _CollectorHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @property
    def records(self) -> list[CollectorRecord]:
        return list(_CollectorHandler.records)


async def run_local_sandbox(request: LocalSandboxRunRequest) -> LocalSandboxRunResponse:
    artifact_path = resolve_artifact_uri(request.artifact_uri)
    telemetry: list[SandboxTelemetry] = []
    violation_detected = False

    with TemporaryDirectory(prefix="aegiscudo-sandbox-") as sandbox_root_str:
        sandbox_root = Path(sandbox_root_str)
        home_dir = sandbox_root / "home"
        work_dir = sandbox_root / "workspace"
        home_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)
        plant_canaries(home_dir)
        canary_snapshot = snapshot_canary_files(home_dir)
        base_env = build_canary_environment(home_dir)

        # Cargo: extract crate once and share project dir across all phases
        cargo_project_dir: Path | None = None
        if request.profile == SandboxProfile.CARGO_BUILD_PROFILE:
            cargo_home = sandbox_root / "cargo-home"
            cargo_home.mkdir(parents=True, exist_ok=True)
            # Preserve the system rustup home so cargo can locate the active toolchain.
            # HOME is changed to the sandbox home dir, which hides ~/.rustup.
            rustup_home = os.environ.get("RUSTUP_HOME") or str(Path.home() / ".rustup")
            base_env = {
                **base_env,
                "CARGO_HOME": str(cargo_home),
                "RUSTUP_HOME": rustup_home,
                "CARGO_TERM_COLOR": "never",
                "CARGO_INCREMENTAL": "0",
            }
            container_dir = work_dir / "cargo-container"
            container_dir.mkdir(parents=True, exist_ok=True)
            cargo_project_dir = await ensure_cargo_workspace(container_dir, artifact_path)
        elif request.profile == SandboxProfile.JVM_BINARY_PROFILE:
            java_tool_options = base_env.get("JAVA_TOOL_OPTIONS", "").strip()
            user_home_flag = f"-Duser.home={home_dir}"
            base_env = {
                **base_env,
                "JAVA_TOOL_OPTIONS": f"{java_tool_options} {user_home_flag}".strip(),
            }

        collector_port_open = is_port_available(9999)
        collector_context = ExfiltrationCollector() if collector_port_open else null_context()
        with collector_context as collector:
            phases = phases_for_profile(request.profile)
            for phase in phases:
                if cargo_project_dir is not None:
                    phase_work_dir = cargo_project_dir
                else:
                    phase_work_dir = work_dir / phase.value
                    phase_work_dir.mkdir(parents=True, exist_ok=True)
                phase_result = await execute_phase(
                    request,
                    artifact_path,
                    home_dir,
                    phase_work_dir,
                    base_env,
                    phase,
                    canary_snapshot,
                    collector.records if collector_port_open else [],
                )
                telemetry.append(phase_result.telemetry)
                violation_detected = violation_detected or phase_result.violation_detected

    return LocalSandboxRunResponse(
        run_id=str(uuid4()),
        state="completed",
        violation_detected=violation_detected,
        telemetry=telemetry,
    )


def build_local_sandbox_profile_registry() -> SandboxProfileRegistry:
    executor = LocalSandboxExecutor()
    return SandboxProfileRegistry(
        {
            SandboxProfile.NPM_INSTALL: executor,
            SandboxProfile.PYTHON_INSTALL: executor,
            SandboxProfile.CARGO_BUILD_PROFILE: executor,
            SandboxProfile.JVM_BINARY_PROFILE: executor,
        }
    )


async def run_sandbox_profile(
    request: LocalSandboxRunRequest,
    *,
    profile_registry: SandboxProfileRegistry | None = None,
) -> LocalSandboxRunResponse:
    registry = profile_registry or build_local_sandbox_profile_registry()
    executor = registry.resolve(request.profile)
    return await executor.run(request)


async def execute_phase(
    request: LocalSandboxRunRequest,
    artifact_path: Path,
    home_dir: Path,
    work_dir: Path,
    base_env: dict[str, str],
    phase: SandboxPhase,
    baseline_snapshot: dict[str, str],
    collector_before: list[CollectorRecord],
) -> PhaseResult:
    run_id = uuid4()
    start = time.monotonic()
    events: list[SandboxTelemetryEvent] = []
    violation_detected = False
    jvm_filesystem_before: dict[str, FileSnapshot] | None = None

    if request.profile == SandboxProfile.NPM_INSTALL:
        await ensure_npm_workspace(work_dir)
        command = npm_command_for_phase(phase, artifact_path)
    elif request.profile == SandboxProfile.CARGO_BUILD_PROFILE:
        # work_dir is the shared extracted cargo project directory
        phase_env = dict(base_env)
        if phase in (SandboxPhase.H, SandboxPhase.F):
            # Deny Cargo registry network after dependency fetch
            phase_env["CARGO_NET_OFFLINE"] = "true"
        base_env = phase_env
        command = cargo_command_for_phase(phase, work_dir)
    elif request.profile == SandboxProfile.JVM_BINARY_PROFILE:
        command = java_command_for_phase(phase, artifact_path, work_dir)
    else:
        await ensure_python_workspace(work_dir)
        if phase == SandboxPhase.G:
            install_command = python_command_for_phase(SandboxPhase.D, artifact_path, request.import_name)
            if install_command is not None:
                await run_subprocess(
                    install_command,
                    cwd=work_dir,
                    env=base_env,
                    timeout_seconds=request.timeout_seconds,
                )
        command = python_command_for_phase(phase, artifact_path, request.import_name)

    if command is not None:
        if request.profile == SandboxProfile.JVM_BINARY_PROFILE and phase == SandboxPhase.G:
            jvm_filesystem_before = snapshot_filesystem_state(
                {
                    "home": home_dir,
                    "workspace": work_dir,
                }
            )
        completed = await run_subprocess(
            command,
            cwd=work_dir,
            env=base_env,
            timeout_seconds=request.timeout_seconds,
        )
        if completed.timeout:
            events.append(
                SandboxTelemetryEvent(
                    type="sandbox-timeout",
                    severity=Severity.MEDIUM,
                    message=f"phase {phase.value} exceeded timeout",
                )
            )
        elif completed.returncode != 0:
            events.append(
                SandboxTelemetryEvent(
                    type="process-nonzero-exit",
                    severity=Severity.LOW,
                    message=f"phase {phase.value} exited with code {completed.returncode}",
                )
            )

        # Dependency tree capture for Cargo phase H
        if (
            request.profile == SandboxProfile.CARGO_BUILD_PROFILE
            and phase == SandboxPhase.H
            and not completed.timeout
            and completed.returncode == 0
        ):
            tree_events = _cargo_tree_events(completed.stdout)
            events.extend(tree_events)

        # Post-build artifact inspection for Cargo phase F
        if (
            request.profile == SandboxProfile.CARGO_BUILD_PROFILE
            and phase == SandboxPhase.F
            and not completed.timeout
        ):
            inspect_events, inspect_violation, _inspect_needs_hifi = await post_cargo_build_inspection(work_dir)
            events.extend(inspect_events)
            violation_detected = violation_detected or inspect_violation

        if (
            request.profile == SandboxProfile.JVM_BINARY_PROFILE
            and phase == SandboxPhase.G
            and not completed.timeout
        ):
            events.extend(jvm_process_execution_events(completed.observed_processes))
            if jvm_filesystem_before is not None:
                events.extend(
                    jvm_filesystem_write_events(
                        jvm_filesystem_before,
                        snapshot_filesystem_state(
                            {
                                "home": home_dir,
                                "workspace": work_dir,
                            }
                        ),
                    )
                )

        if (
            request.profile == SandboxProfile.JVM_BINARY_PROFILE
            and phase == SandboxPhase.G
            and not completed.timeout
            and completed.returncode == 0
        ):
            events.extend(
                jvm_class_load_events(
                    f"{completed.stdout}\n{completed.stderr}",
                    infer_java_load_targets(artifact_path),
                )
            )

    elapsed = time.monotonic() - start
    collector_after = list(_CollectorHandler.records)
    new_records = collector_after[len(collector_before) :]
    record_events, record_violation = collector_events(new_records)
    events.extend(record_events)
    violation_detected = violation_detected or record_violation

    changed_files = changed_canary_files(home_dir, baseline_snapshot)
    if changed_files:
        events.append(
            SandboxTelemetryEvent(
                type="ai-canary-file-modified",
                severity=Severity.CRITICAL,
                message=f"canary files modified: {', '.join(changed_files)}",
            )
        )
        violation_detected = True

    events.append(
        SandboxTelemetryEvent(
            type="phase-completed",
            severity=Severity.INFO,
            message=f"phase {phase.value} completed in {elapsed:.2f}s",
        )
    )
    return PhaseResult(
        telemetry=SandboxTelemetry(
            run_id=run_id,
            profile=request.profile,
            phase=phase,
            egress_mode=EgressMode.DENY_ALL,
            events=events,
        ),
        violation_detected=violation_detected,
    )


@dataclass(frozen=True)
class CompletedProcess:
    returncode: int
    stdout: str
    stderr: str
    timeout: bool
    observed_processes: list[ObservedProcess]


async def run_subprocess(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
) -> CompletedProcess:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    observed_processes: dict[int, ObservedProcess] = {}
    monitor_task = asyncio.create_task(monitor_child_processes(process.pid, observed_processes))
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout_seconds)
        return CompletedProcess(
            returncode=process.returncode or 0,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            timeout=False,
            observed_processes=sorted_observed_processes(observed_processes),
        )
    except TimeoutError:
        process.kill()
        await process.communicate()
        return CompletedProcess(
            returncode=-9,
            stdout="",
            stderr="",
            timeout=True,
            observed_processes=sorted_observed_processes(observed_processes),
        )
    finally:
        monitor_task.cancel()
        with suppress(asyncio.CancelledError):
            await monitor_task


def resolve_artifact_uri(value: str) -> Path:
    parsed = urlparse(value)
    if parsed.scheme in {"", "file"}:
        if parsed.scheme == "file":
            return Path(parsed.path)
        return Path(value)
    raise ValueError(f"unsupported artifact URI scheme: {parsed.scheme}")


def phases_for_profile(profile: SandboxProfile) -> tuple[SandboxPhase, ...]:
    if profile == SandboxProfile.NPM_INSTALL:
        return (SandboxPhase.A, SandboxPhase.D, SandboxPhase.E)
    if profile == SandboxProfile.CARGO_BUILD_PROFILE:
        return (SandboxPhase.A, SandboxPhase.D, SandboxPhase.E, SandboxPhase.H, SandboxPhase.F)
    if profile == SandboxProfile.JVM_BINARY_PROFILE:
        return (SandboxPhase.A, SandboxPhase.G)
    return (SandboxPhase.A, SandboxPhase.D, SandboxPhase.G)


async def ensure_npm_workspace(work_dir: Path) -> None:
    package_json = work_dir / "package.json"
    if not package_json.exists():
        package_json.write_text('{"name":"sandbox-runner","private":true}\n', encoding="utf-8")


def npm_command_for_phase(phase: SandboxPhase, artifact_path: Path) -> list[str] | None:
    artifact = str(artifact_path)
    if phase == SandboxPhase.A:
        return None
    if phase == SandboxPhase.D:
        return ["npm", "install", "--ignore-scripts", artifact]
    if phase == SandboxPhase.E:
        return ["npm", "install", artifact]
    return None


async def ensure_python_workspace(work_dir: Path) -> None:
    venv_dir = work_dir / ".venv"
    if not venv_dir.exists():
        await run_subprocess(
            [sys_executable(), "-m", "venv", str(venv_dir)],
            cwd=work_dir,
            env=os.environ.copy(),
            timeout_seconds=30,
        )


def python_command_for_phase(
    phase: SandboxPhase,
    artifact_path: Path,
    import_name: str | None,
) -> list[str] | None:
    venv_python = str(Path(".venv") / "bin" / "python")
    artifact = str(artifact_path)
    if phase == SandboxPhase.A:
        return None
    if phase == SandboxPhase.D:
        return [venv_python, "-m", "pip", "install", "--no-deps", artifact]
    if phase == SandboxPhase.G:
        module_name = import_name or infer_python_import_name(artifact_path)
        return [venv_python, "-c", f"import {module_name}"]
    return None


def infer_python_import_name(artifact_path: Path) -> str:
    file_name = artifact_path.name
    if file_name.endswith(".tar.gz"):
        stem = file_name[: -len(".tar.gz")]
    else:
        stem = artifact_path.stem
    parts = stem.split("-")
    return parts[0].replace("-", "_")


def build_canary_environment(home_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(CANARY_ENVIRONMENT)
    env["HOME"] = str(home_dir)
    env["USERPROFILE"] = str(home_dir)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    return env


def plant_canaries(home_dir: Path) -> None:
    for relative_path, contents in CANARY_FILES.items():
        path = home_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")


def snapshot_canary_files(home_dir: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for relative_path in CANARY_FILES:
        snapshot[relative_path] = (home_dir / relative_path).read_text(encoding="utf-8")
    return snapshot


def changed_canary_files(home_dir: Path, baseline_snapshot: dict[str, str]) -> list[str]:
    changed: list[str] = []
    for relative_path, baseline in baseline_snapshot.items():
        current = (home_dir / relative_path).read_text(encoding="utf-8")
        if current != baseline:
            changed.append(relative_path)
    return changed


def collector_events(records: list[CollectorRecord]) -> tuple[list[SandboxTelemetryEvent], bool]:
    events: list[SandboxTelemetryEvent] = []
    violation_detected = False
    for record in records:
        payload = record.payload or {}
        redacted_payload = redact_mapping(payload if isinstance(payload, dict) else {})
        destination_url, destination_host, destination_ip = collector_destination_fields(record)
        events.append(
            SandboxTelemetryEvent(
                type="outbound-network-attempt",
                severity=Severity.HIGH,
                message=(
                    "captured outbound sandbox exfil attempt to loopback collector "
                    f"with payload {json.dumps(redacted_payload, sort_keys=True)}"
                ),
                destination_url=destination_url,
                destination_host=destination_host,
                destination_ip=destination_ip,
            )
        )
        violation_detected = True
        env_mapping = payload.get("env") if isinstance(payload, dict) else None
        contains_canary = False
        if isinstance(env_mapping, dict) and payload_contains_canary_values(env_mapping):
            contains_canary = True
        elif raw_payload_contains_canary_values(record.raw_body):
            contains_canary = True

        if contains_canary:
            events.append(
                SandboxTelemetryEvent(
                    type="canary-secret-access",
                    severity=Severity.CRITICAL,
                    message="captured exfil payload containing planted canary credential values",
                )
            )
            violation_detected = True
    return events, violation_detected


def collector_destination_fields(
    record: CollectorRecord,
) -> tuple[str | None, str | None, str | None]:
    host_header = record.headers.get("host", "").strip()
    if not host_header:
        return None, None, None

    destination_host = normalized_destination_host(host_header)
    destination_ip = normalized_destination_ip(destination_host)
    path = record.path if record.path.startswith("/") else f"/{record.path}"
    destination_url = f"http://{host_header}{path}"
    return destination_url, destination_host, destination_ip


def normalized_destination_host(host_header: str) -> str:
    if host_header.startswith("[") and "]" in host_header:
        return host_header[1 : host_header.index("]")]
    return host_header.rsplit(":", 1)[0] if host_header.count(":") == 1 else host_header


def normalized_destination_ip(host: str) -> str | None:
    if host == "localhost":
        return "127.0.0.1"
    try:
        return str(ip_address(host))
    except ValueError:
        return None


def payload_contains_canary_values(payload: dict[str, Any]) -> bool:
    values = {str(value) for value in payload.values()}
    return any(canary in values for canary in CANARY_ENVIRONMENT.values())


def raw_payload_contains_canary_values(payload: str) -> bool:
    return any(canary in payload for canary in CANARY_ENVIRONMENT.values())


def is_port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def sys_executable() -> str:
    return shutil.which("python3") or shutil.which("python") or "python3"


def java_executable() -> str:
    return shutil.which("java") or "java"


def sorted_observed_processes(
    observed_processes: Mapping[int, ObservedProcess],
) -> list[ObservedProcess]:
    return sorted(observed_processes.values(), key=lambda process: process.pid)


async def monitor_child_processes(
    root_pid: int,
    observed_processes: dict[int, ObservedProcess],
) -> None:
    while True:
        for process in descendant_processes(root_pid):
            observed_processes.setdefault(process.pid, process)
        await asyncio.sleep(0.05)


def descendant_processes(root_pid: int) -> list[ObservedProcess]:
    proc_root = Path("/proc")
    if not proc_root.exists():
        return []

    process_table: dict[int, ObservedProcess] = {}
    child_map: dict[int, list[int]] = {}
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return []

    for entry in entries:
        if not entry.name.isdigit():
            continue
        process = read_process_info(int(entry.name))
        if process is None:
            continue
        process_table[process.pid] = process
        if process.ppid is not None:
            child_map.setdefault(process.ppid, []).append(process.pid)

    descendants: list[ObservedProcess] = []
    queue = list(child_map.get(root_pid, []))
    seen: set[int] = set()
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        process = process_table.get(pid)
        if process is None:
            continue
        descendants.append(process)
        queue.extend(child_map.get(pid, []))
    return descendants


def read_process_info(pid: int) -> ObservedProcess | None:
    proc_dir = Path("/proc") / str(pid)
    status_path = proc_dir / "status"
    cmdline_path = proc_dir / "cmdline"
    try:
        name: str | None = None
        ppid: int | None = None
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Name:\t"):
                name = line.split("\t", 1)[1].strip()
            elif line.startswith("PPid:\t"):
                parent = line.split("\t", 1)[1].strip()
                ppid = int(parent) if parent.isdigit() else None

        command_name = ""
        try:
            command_name = Path(
                cmdline_path.read_bytes().split(b"\0", 1)[0].decode("utf-8", errors="replace")
            ).name
        except OSError:
            command_name = ""

        executable: str | None = None
        try:
            executable = os.readlink(proc_dir / "exe")
        except OSError:
            executable = None

        display_name = command_name or name or (Path(executable).name if executable else f"pid-{pid}")
        return ObservedProcess(pid=pid, ppid=ppid, name=display_name, executable=executable)
    except OSError:
        return None


@contextmanager
def null_context() -> Any:
    yield type("NullCollector", (), {"records": []})()

# ---------------------------------------------------------------------------
# JVM sandbox helpers
# ---------------------------------------------------------------------------


def java_command_for_phase(phase: SandboxPhase, artifact_path: Path, work_dir: Path) -> list[str] | None:
    if phase == SandboxPhase.A:
        return None
    if phase != SandboxPhase.G:
        return None

    selected_classes = infer_java_load_targets(artifact_path)
    if not selected_classes:
        raise ValueError(f"unable to infer JVM load targets from artifact: {artifact_path}")

    probe_path = work_dir / "JvmClassLoadProbe.java"
    if not probe_path.exists():
        probe_path.write_text(_JVM_CLASS_LOAD_PROBE, encoding="utf-8")

    return [java_executable(), "-verbose:class", str(probe_path), str(artifact_path), *selected_classes]


def infer_java_load_targets(artifact_path: Path) -> list[str]:
    if artifact_path.suffix.lower() not in {".jar", ".war", ".ear"}:
        raise ValueError(f"unsupported JVM artifact: {artifact_path}")

    with zipfile.ZipFile(artifact_path) as archive:
        selected: list[str] = []
        main_class = infer_java_main_class(archive)
        if main_class is not None:
            selected.append(main_class)

        for entry_name in archive.namelist():
            if not entry_name.endswith(".class"):
                continue
            if entry_name.startswith("META-INF/") or entry_name.endswith(("module-info.class", "package-info.class")):
                continue

            class_name = entry_name[: -len(".class")].replace("/", ".")
            if "$" in class_name or class_name in selected:
                continue
            selected.append(class_name)
            if len(selected) >= 3:
                break

    return selected


def infer_java_main_class(archive: zipfile.ZipFile) -> str | None:
    try:
        manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
    except KeyError:
        return None

    for line in manifest.splitlines():
        if line.lower().startswith("main-class:"):
            main_class = line.split(":", 1)[1].strip()
            return main_class or None
    return None


def jvm_class_load_events(output: str, selected_classes: list[str]) -> list[SandboxTelemetryEvent]:
    loaded: set[str] = set()
    modern_pattern = re.compile(r"\[.*?\]\[info\]\[class,load\]\s+([A-Za-z0-9_.$/]+)\s+source:")
    legacy_pattern = re.compile(r"^\[Loaded\s+([A-Za-z0-9_.$/]+)\s+from\s+.*\]$", re.MULTILINE)

    for match in modern_pattern.finditer(output):
        loaded.add(match.group(1))
    for match in legacy_pattern.finditer(output):
        loaded.add(match.group(1))

    events: list[SandboxTelemetryEvent] = []
    for class_name in selected_classes:
        if class_name in loaded:
            events.append(
                SandboxTelemetryEvent(
                    type="jvm-class-loaded",
                    severity=Severity.INFO,
                    message=f"loaded selected JVM class {class_name}",
                )
            )
    return events


def jvm_process_execution_events(processes: list[ObservedProcess]) -> list[SandboxTelemetryEvent]:
    if not processes:
        return []

    samples = [f"{process.name} [pid {process.pid}]" for process in processes[:5]]
    if len(processes) > 5:
        samples.append(f"+{len(processes) - 5} more")

    return [
        SandboxTelemetryEvent(
            type="jvm-process-execution-observed",
            severity=Severity.HIGH,
            message=(
                "observed child process execution during JVM class load: "
                + ", ".join(samples)
            ),
        )
    ]


def snapshot_filesystem_state(paths: Mapping[str, Path]) -> dict[str, FileSnapshot]:
    snapshot: dict[str, FileSnapshot] = {}
    for label, root in paths.items():
        if not root.exists():
            continue
        try:
            files = list(root.rglob("*"))
        except OSError:
            continue
        for path in files:
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            key = f"{label}/{relative}"
            if is_ignored_jvm_filesystem_path(key):
                continue
            try:
                stat_result = path.stat()
            except OSError:
                continue
            snapshot[key] = FileSnapshot(size=stat_result.st_size, mtime_ns=stat_result.st_mtime_ns)
    return snapshot


def is_ignored_jvm_filesystem_path(path: str) -> bool:
    file_name = path.rsplit("/", 1)[-1]
    return (
        file_name == "JvmClassLoadProbe.java"
        or file_name == "JvmClassLoadProbe.class"
        or file_name.startswith("JvmClassLoadProbe$")
    )


def jvm_filesystem_write_events(
    before: Mapping[str, FileSnapshot],
    after: Mapping[str, FileSnapshot],
) -> list[SandboxTelemetryEvent]:
    created = sorted(path for path in after.keys() - before.keys())
    modified = sorted(path for path in before.keys() & after.keys() if before[path] != after[path])
    if not created and not modified:
        return []

    parts: list[str] = []
    if created:
        parts.append(f"created {summarize_examples(created)}")
    if modified:
        parts.append(f"modified {summarize_examples(modified)}")

    return [
        SandboxTelemetryEvent(
            type="jvm-filesystem-write-observed",
            severity=Severity.MEDIUM,
            message="observed JVM filesystem writes in sandbox: " + "; ".join(parts),
        )
    ]


def summarize_examples(values: list[str], limit: int = 5) -> str:
    if len(values) <= limit:
        return ", ".join(values)
    return ", ".join(values[:limit]) + f", +{len(values) - limit} more"


# ---------------------------------------------------------------------------
# Cargo sandbox helpers
# ---------------------------------------------------------------------------


async def ensure_cargo_workspace(container_dir: Path, artifact_path: Path) -> Path:
    """Copy source dir or extract .crate archive into container_dir. Returns the Cargo project root."""
    project_dir = container_dir / "project"
    if project_dir.exists():
        return _find_cargo_project_root(project_dir)

    project_dir.mkdir(parents=True, exist_ok=True)

    if artifact_path.is_dir():
        shutil.copytree(
            str(artifact_path),
            str(project_dir / artifact_path.name),
            ignore=shutil.ignore_patterns("target"),
        )
        return _find_cargo_project_root(project_dir)

    name = artifact_path.name
    if name.endswith(".crate") or name.endswith(".tar.gz"):
        with tarfile.open(str(artifact_path), "r:gz") as tf:
            tf.extractall(str(project_dir), filter="data")
        return _find_cargo_project_root(project_dir)

    raise ValueError(f"unsupported Cargo artifact: {artifact_path}")


def _find_cargo_project_root(directory: Path) -> Path:
    """Return the directory containing Cargo.toml, searching one level deep."""
    if (directory / "Cargo.toml").exists():
        return directory
    for child in sorted(directory.iterdir()):
        if child.is_dir() and (child / "Cargo.toml").exists():
            return child
    return directory


def cargo_command_for_phase(phase: SandboxPhase, project_dir: Path) -> list[str] | None:
    manifest = str(project_dir / "Cargo.toml")
    if phase == SandboxPhase.A:
        return None
    if phase == SandboxPhase.D:
        return [
            "cargo", "metadata",
            "--format-version=1", "--no-deps", "--locked",
            "--manifest-path", manifest,
        ]
    if phase == SandboxPhase.E:
        return ["cargo", "fetch", "--locked", "--manifest-path", manifest]
    if phase == SandboxPhase.H:
        return ["cargo", "tree", "--locked", "--manifest-path", manifest]
    if phase == SandboxPhase.F:
        return ["cargo", "build", "--locked", "--manifest-path", manifest]
    return None


def _is_native_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            magic = fh.read(4)
        return (
            magic == _ELF_MAGIC
            or magic[:2] == _PE_MAGIC[:2]
            or magic in _MACHO_MAGIC
        )
    except OSError:
        return False


def _collect_native_artifacts(directory: Path) -> list[Path]:
    """Find ELF / Mach-O / PE binaries under a directory."""
    candidates: list[Path] = []
    try:
        for path in directory.rglob("*"):
            if path.is_file() and _is_native_binary(path):
                candidates.append(path)
    except (PermissionError, OSError):
        pass
    return candidates


def _inspect_native_artifact(artifact: Path) -> tuple[list[SandboxTelemetryEvent], bool]:
    """Run strings / nm on a native binary and flag suspicious content."""
    events: list[SandboxTelemetryEvent] = []
    violation = False

    events.append(
        SandboxTelemetryEvent(
            type="cargo-native-artifact-detected",
            severity=Severity.MEDIUM,
            message=f"native binary found in build output: {artifact.name}",
        )
    )

    strings_bin = shutil.which("strings")
    if strings_bin:
        try:
            result = _subprocess.run(
                [strings_bin, "--", str(artifact)],
                capture_output=True, text=True, timeout=10,
            )
            suspicious_lines = [
                line.strip()
                for line in result.stdout.splitlines()
                if any(pat in line.lower() for pat in _SUSPICIOUS_STRINGS)
            ]
            if suspicious_lines:
                violation = True
                events.append(
                    SandboxTelemetryEvent(
                        type="native-artifact-escalation",
                        severity=Severity.CRITICAL,
                        message=(
                            f"suspicious strings in {artifact.name}: "
                            + "; ".join(suspicious_lines[:5])
                        ),
                    )
                )
        except Exception:
            pass

    nm_bin = shutil.which("nm")
    rustfilt_bin = shutil.which("rustfilt")
    if nm_bin:
        try:
            nm_result = _subprocess.run(
                [nm_bin, "--demangle", "--", str(artifact)],
                capture_output=True, text=True, timeout=15,
            )
            symbols_raw = nm_result.stdout
            if rustfilt_bin:
                rf_result = _subprocess.run(
                    [rustfilt_bin],
                    input=nm_result.stdout,
                    capture_output=True, text=True, timeout=10,
                )
                symbols_raw = rf_result.stdout
            suspicious_syms = [
                line.strip()
                for line in symbols_raw.splitlines()
                if any(
                    pat in line
                    for pat in (
                        "std::net",
                        "TcpStream",
                        "UdpSocket",
                        "std::process::Command",
                        "libc::execv",
                    )
                )
            ]
            if suspicious_syms:
                violation = True
                events.append(
                    SandboxTelemetryEvent(
                        type="native-artifact-escalation",
                        severity=Severity.CRITICAL,
                        message=(
                            f"suspicious symbols in {artifact.name}: "
                            + "; ".join(suspicious_syms[:5])
                        ),
                    )
                )
        except Exception:
            pass

    return events, violation


_MAX_TREE_OUTPUT_CHARS = 4000
_PROC_MACRO_MARKER = "(proc-macro)"


def _cargo_tree_events(tree_output: str) -> list[SandboxTelemetryEvent]:
    """Emit telemetry events derived from `cargo tree` stdout output."""
    events: list[SandboxTelemetryEvent] = []
    if not tree_output.strip():
        return events

    # Capture the full dependency tree output (truncated for storage)
    summary = tree_output[:_MAX_TREE_OUTPUT_CHARS]
    if len(tree_output) > _MAX_TREE_OUTPUT_CHARS:
        summary += f"\n... ({len(tree_output) - _MAX_TREE_OUTPUT_CHARS} chars truncated)"
    events.append(
        SandboxTelemetryEvent(
            type="cargo-dependency-tree",
            severity=Severity.INFO,
            message=summary,
        )
    )

    # Flag transitive proc-macro crates — they execute arbitrary code at compile time
    proc_macro_lines = [
        line.strip()
        for line in tree_output.splitlines()
        if _PROC_MACRO_MARKER in line
    ]
    if proc_macro_lines:
        sample = ", ".join(proc_macro_lines[:5])
        events.append(
            SandboxTelemetryEvent(
                type="cargo-proc-macro-in-tree",
                severity=Severity.MEDIUM,
                message=f"{len(proc_macro_lines)} proc-macro crate(s) in dependency tree: {sample}",
            )
        )

    return events


async def post_cargo_build_inspection(
    project_dir: Path,
) -> tuple[list[SandboxTelemetryEvent], bool, bool]:
    """Inspect OUT_DIR outputs and native artifacts produced by cargo build."""
    events: list[SandboxTelemetryEvent] = []
    violation = False
    needs_hifi_detonation = False

    target_debug = project_dir / "target" / "debug"
    if not target_debug.exists():
        return events, violation, needs_hifi_detonation

    out_dirs = sorted(target_debug.glob("build/*/out"))
    if out_dirs:
        out_files: list[str] = []
        for out_dir in out_dirs:
            out_files.extend(
                str(p.relative_to(project_dir))
                for p in out_dir.rglob("*")
                if p.is_file()
            )
        events.append(
            SandboxTelemetryEvent(
                type="cargo-build-out-dir",
                severity=Severity.MEDIUM,
                message=(
                    f"build script OUT_DIR produced {len(out_files)} file(s)"
                    + (f": {', '.join(out_files[:3])}" if out_files else "")
                ),
            )
        )

    for artifact in _collect_native_artifacts(target_debug):
        artifact_events, artifact_violation = _inspect_native_artifact(artifact)
        events.extend(artifact_events)
        violation = violation or artifact_violation
        if artifact_violation:
            needs_hifi_detonation = True

    if needs_hifi_detonation:
        events.append(
            SandboxTelemetryEvent(
                type="cargo-native-escalation-pending-hifi",
                severity=Severity.CRITICAL,
                message=(
                    "native artifact with suspicious symbols detected; "
                    "high-fidelity detonation required for definitive analysis"
                ),
            )
        )

    return events, violation, needs_hifi_detonation
