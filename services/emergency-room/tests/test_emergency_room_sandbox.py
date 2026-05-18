import subprocess
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from aegiscudo_common.contracts import SandboxProfile
from emergency_room.app import app
from emergency_room.sandbox import (
    CANARY_FILES,
    _cargo_tree_events,
    infer_python_import_name,
    post_cargo_build_inspection,
    resolve_artifact_uri,
)
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[3]
NPM_FIXTURE = ROOT / "samples" / "malicious" / "npm" / "env-snoop" / "env-snoop-1.0.0.tgz"
AI_CANARY_FIXTURE = ROOT / "samples" / "malicious" / "npm" / "ai-canary-scribbler"
TIMEOUT_FIXTURE = ROOT / "samples" / "malicious" / "npm" / "timeout-sleeper"
PYPI_FIXTURE = ROOT / "samples" / "malicious" / "pypi" / "env-snoop" / "dist" / "env_snoop-1.0.0.tar.gz"
PYPI_TIMEOUT_FIXTURE = ROOT / "samples" / "malicious" / "pypi" / "timeout-sleeper"
RUST_FIXTURE = ROOT / "samples" / "malicious" / "rust" / "env-snoop"
JAVA_FIXTURE = ROOT / "samples" / "malicious" / "java" / "env-snoop" / "target" / "env-snoop-1.0.0.jar"


def test_resolve_file_uri_and_import_name() -> None:
    resolved = resolve_artifact_uri(PYPI_FIXTURE.as_uri())
    assert resolved == PYPI_FIXTURE
    assert infer_python_import_name(PYPI_FIXTURE) == "env_snoop"


def test_ai_editor_settings_canaries_are_planted() -> None:
    assert ".cursor/settings.json" in CANARY_FILES
    assert ".vscode/settings.json" in CANARY_FILES


@pytest.mark.skipif(not NPM_FIXTURE.exists(), reason="npm fixture missing")
def test_local_npm_sandbox_detects_canary_exfiltration() -> None:
    if not shutil_which("npm"):
        pytest.skip("npm is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.NPM_INSTALL.value,
            "artifact_uri": NPM_FIXTURE.as_uri(),
            "timeout_seconds": 30,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    events = [event for phase in body["telemetry"] for event in phase["events"]]
    event_types = {event["type"] for event in events}
    assert "outbound-network-attempt" in event_types
    assert "canary-secret-access" in event_types
    outbound_event = next(event for event in events if event["type"] == "outbound-network-attempt")
    assert outbound_event["destination_url"] == "http://localhost:9999/collect"
    assert outbound_event["destination_host"] == "localhost"
    assert outbound_event["destination_ip"] == "127.0.0.1"


@pytest.mark.skipif(not AI_CANARY_FIXTURE.exists(), reason="ai canary fixture missing")
def test_local_npm_sandbox_detects_ai_canary_file_modification() -> None:
    if not shutil_which("npm"):
        pytest.skip("npm is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.NPM_INSTALL.value,
            "artifact_uri": AI_CANARY_FIXTURE.as_uri(),
            "timeout_seconds": 30,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    ai_canary_events = [
        event
        for phase in body["telemetry"]
        for event in phase["events"]
        if event["type"] == "ai-canary-file-modified"
    ]
    assert ai_canary_events
    assert ".cursorrules" in ai_canary_events[0]["message"]
    assert ".github/copilot-instructions.md" in ai_canary_events[0]["message"]


@pytest.mark.skipif(not TIMEOUT_FIXTURE.exists(), reason="timeout fixture missing")
def test_local_npm_sandbox_records_timeout_event() -> None:
    if not shutil_which("npm"):
        pytest.skip("npm is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.NPM_INSTALL.value,
            "artifact_uri": TIMEOUT_FIXTURE.as_uri(),
            "timeout_seconds": 1,
        },
    )

    assert response.status_code == 200
    body = response.json()
    event_types = {
        event["type"]
        for phase in body["telemetry"]
        for event in phase["events"]
    }
    assert "sandbox-timeout" in event_types


@pytest.mark.skipif(not PYPI_TIMEOUT_FIXTURE.exists(), reason="python timeout fixture missing")
def test_local_python_sandbox_records_timeout_event() -> None:
    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.PYTHON_INSTALL.value,
            "artifact_uri": PYPI_TIMEOUT_FIXTURE.as_uri(),
            "import_name": "timeout_sleeper",
            "timeout_seconds": 1,
        },
    )

    assert response.status_code == 200
    body = response.json()
    event_types = {
        event["type"]
        for phase in body["telemetry"]
        for event in phase["events"]
    }
    assert "sandbox-timeout" in event_types


@pytest.mark.skipif(not PYPI_FIXTURE.exists(), reason="pypi fixture missing")
def test_local_python_sandbox_detects_canary_exfiltration() -> None:
    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.PYTHON_INSTALL.value,
            "artifact_uri": PYPI_FIXTURE.as_uri(),
            "import_name": "env_snoop",
            "timeout_seconds": 45,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    phases = {phase["phase"] for phase in body["telemetry"]}
    assert "D" in phases
    assert "G" in phases
    events = [event for phase in body["telemetry"] for event in phase["events"]]
    event_types = {event["type"] for event in events}
    assert "outbound-network-attempt" in event_types
    assert "canary-secret-access" in event_types
    outbound_event = next(event for event in events if event["type"] == "outbound-network-attempt")
    assert outbound_event["destination_url"] == "http://localhost:9999/collect"
    assert outbound_event["destination_host"] == "localhost"
    assert outbound_event["destination_ip"] == "127.0.0.1"


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


def test_cargo_tree_events_empty_output_returns_no_events() -> None:
    events = _cargo_tree_events("")
    assert events == []


def test_cargo_tree_events_whitespace_only_returns_no_events() -> None:
    events = _cargo_tree_events("   \n  \n")
    assert events == []


def test_cargo_tree_events_emits_dependency_tree_event() -> None:
    tree = "my-crate v0.1.0\n└── serde v1.0.0\n"
    events = _cargo_tree_events(tree)
    event_types = [e.type for e in events]
    assert "cargo-dependency-tree" in event_types
    tree_event = next(e for e in events if e.type == "cargo-dependency-tree")
    assert "my-crate" in tree_event.message
    assert "serde" in tree_event.message


def test_cargo_tree_events_detects_proc_macro_crates() -> None:
    tree = (
        "my-crate v0.1.0\n"
        "├── serde v1.0.0\n"
        "│   └── serde_derive v1.0.0 (proc-macro)\n"
        "└── tokio v1.0.0\n"
    )
    events = _cargo_tree_events(tree)
    event_types = [e.type for e in events]
    assert "cargo-proc-macro-in-tree" in event_types
    proc_event = next(e for e in events if e.type == "cargo-proc-macro-in-tree")
    assert "serde_derive" in proc_event.message


def test_cargo_tree_events_no_proc_macro_crates_skips_that_event() -> None:
    tree = "my-crate v0.1.0\n└── serde v1.0.0\n"
    events = _cargo_tree_events(tree)
    event_types = [e.type for e in events]
    assert "cargo-proc-macro-in-tree" not in event_types


def test_cargo_tree_events_truncates_long_output() -> None:
    long_output = "x" * 5000
    events = _cargo_tree_events(long_output)
    tree_event = next(e for e in events if e.type == "cargo-dependency-tree")
    assert "truncated" in tree_event.message


@pytest.mark.skipif(not RUST_FIXTURE.exists(), reason="rust env-snoop fixture missing")
def test_local_cargo_sandbox_detects_build_script_exfiltration() -> None:
    if not shutil_which("cargo"):
        pytest.skip("cargo is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.CARGO_BUILD_PROFILE.value,
            "artifact_uri": RUST_FIXTURE.as_uri(),
            "timeout_seconds": 120,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    phases = {phase["phase"] for phase in body["telemetry"]}
    assert "D" in phases
    assert "E" in phases
    assert "F" in phases
    events = [event for phase in body["telemetry"] for event in phase["events"]]
    event_types = {event["type"] for event in events}
    assert "outbound-network-attempt" in event_types
    assert "canary-secret-access" in event_types
    outbound_event = next(event for event in events if event["type"] == "outbound-network-attempt")
    assert outbound_event["destination_url"] == "http://localhost/collect"
    assert outbound_event["destination_host"] == "localhost"
    assert outbound_event["destination_ip"] == "127.0.0.1"


@pytest.mark.skipif(not JAVA_FIXTURE.exists(), reason="java env-snoop fixture missing")
def test_local_jvm_sandbox_detects_class_load_exfiltration() -> None:
    if not shutil_which("java"):
        pytest.skip("java is not installed")

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.JVM_BINARY_PROFILE.value,
            "artifact_uri": JAVA_FIXTURE.as_uri(),
            "timeout_seconds": 120,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["violation_detected"] is True
    phases = {phase["phase"] for phase in body["telemetry"]}
    assert "A" in phases
    assert "G" in phases
    events = [event for phase in body["telemetry"] for event in phase["events"]]
    event_types = {event["type"] for event in events}
    assert "outbound-network-attempt" in event_types
    assert "canary-secret-access" in event_types
    outbound_event = next(event for event in events if event["type"] == "outbound-network-attempt")
    assert outbound_event["destination_url"] == "http://localhost:9999/collect"
    assert outbound_event["destination_host"] == "localhost"
    assert outbound_event["destination_ip"] == "127.0.0.1"


def build_runtime_snoop_jar(tmp_path: Path) -> Path:
    source_dir = tmp_path / "src" / "main" / "java" / "com" / "example" / "runtimesnoop"
    source_dir.mkdir(parents=True, exist_ok=True)
    source_path = source_dir / "RuntimeSnoop.java"
    source_path.write_text(
        textwrap.dedent(
            """
            package com.example.runtimesnoop;

            import java.nio.charset.StandardCharsets;
            import java.nio.file.Files;
            import java.nio.file.Path;

            public class RuntimeSnoop {
                static {
                    try {
                        Files.write(
                            Path.of(System.getProperty("user.home"), "jvm-marker.txt"),
                            "marker".getBytes(StandardCharsets.UTF_8)
                        );
                        Process child = new ProcessBuilder(
                            "/bin/sh",
                            "-c",
                            "echo runtime-child && sleep 1"
                        ).start();
                        child.getInputStream().readAllBytes();
                        child.waitFor();
                    } catch (Exception ignored) {
                        // Keep the fixture deterministic for sandbox assertions.
                    }
                }

                public static void main(String[] args) {
                }
            }
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    classes_dir = tmp_path / "classes"
    classes_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["javac", "--release", "11", "-d", str(classes_dir), str(source_path)],
        check=True,
        capture_output=True,
        text=True,
    )

    jar_path = tmp_path / "runtime-snoop.jar"
    subprocess.run(
        [
            "jar",
            "--create",
            "--file",
            str(jar_path),
            "--main-class",
            "com.example.runtimesnoop.RuntimeSnoop",
            "-C",
            str(classes_dir),
            ".",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return jar_path


def test_local_jvm_sandbox_detects_process_and_filesystem_activity(tmp_path: Path) -> None:
    if not (shutil_which("java") and shutil_which("javac") and shutil_which("jar")):
        pytest.skip("java, javac, and jar are required")

    runtime_fixture = build_runtime_snoop_jar(tmp_path)
    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.JVM_BINARY_PROFILE.value,
            "artifact_uri": runtime_fixture.as_uri(),
            "timeout_seconds": 120,
        },
    )

    assert response.status_code == 200
    body = response.json()
    events = [event for phase in body["telemetry"] for event in phase["events"]]
    event_types = {event["type"] for event in events}
    assert "jvm-class-loaded" in event_types
    assert "jvm-process-execution-observed" in event_types
    assert "jvm-filesystem-write-observed" in event_types

    process_event = next(event for event in events if event["type"] == "jvm-process-execution-observed")
    assert "sh" in process_event["message"] or "sleep" in process_event["message"]

    filesystem_event = next(event for event in events if event["type"] == "jvm-filesystem-write-observed")
    assert "home/jvm-marker.txt" in filesystem_event["message"]


@pytest.mark.skipif(not RUST_FIXTURE.exists(), reason="rust env-snoop fixture missing")
def test_local_cargo_sandbox_reports_build_phases_for_benign_crate(tmp_path: Path) -> None:
    if not shutil_which("cargo"):
        pytest.skip("cargo is not installed")

    # Build a minimal no-op crate in tmp_path
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("// empty\n", encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text(
        "[package]\nname = \"benign-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text(
        '# This file is automatically @generated by Cargo.\n'
        '# It is not intended for manual editing.\nversion = 3\n\n'
        '[[package]]\nname = "benign-test"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.CARGO_BUILD_PROFILE.value,
            "artifact_uri": tmp_path.as_uri(),
            "timeout_seconds": 120,
        },
    )

    assert response.status_code == 200
    body = response.json()
    phases = {phase["phase"] for phase in body["telemetry"]}
    assert "A" in phases
    assert "D" in phases
    assert "E" in phases
    assert "H" in phases
    assert "F" in phases


@pytest.mark.skipif(not RUST_FIXTURE.exists(), reason="rust env-snoop fixture missing")
def test_local_cargo_sandbox_cargo_tree_emits_dependency_tree_event(tmp_path: Path) -> None:
    if not shutil_which("cargo"):
        pytest.skip("cargo is not installed")

    # Build a minimal no-op crate in tmp_path
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "lib.rs").write_text("// empty\n", encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text(
        "[package]\nname = \"tree-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text(
        '# This file is automatically @generated by Cargo.\n'
        '# It is not intended for manual editing.\nversion = 3\n\n'
        '[[package]]\nname = "tree-test"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )

    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": SandboxProfile.CARGO_BUILD_PROFILE.value,
            "artifact_uri": tmp_path.as_uri(),
            "timeout_seconds": 120,
        },
    )

    assert response.status_code == 200
    body = response.json()
    phases = {phase["phase"] for phase in body["telemetry"]}
    assert "H" in phases
    event_types = {
        event["type"]
        for phase in body["telemetry"]
        for event in phase["events"]
    }
    assert "cargo-dependency-tree" in event_types


def test_local_cargo_sandbox_rejects_unknown_profile() -> None:
    response = TestClient(app).post(
        "/v1/sandbox/local-run",
        json={
            "profile": "not-a-real-profile",
            "artifact_uri": "file:///tmp/fake.crate",
        },
    )
    assert response.status_code == 422


def test_post_cargo_build_inspection_emits_escalation_event_when_suspicious(
    tmp_path: Path,
) -> None:
    """When _inspect_native_artifact signals a violation, post_cargo_build_inspection
    must append a cargo-native-escalation-pending-hifi event and set needs_hifi_detonation."""
    import asyncio
    from emergency_room.sandbox import SandboxTelemetryEvent, Severity

    # Minimal target/debug directory with a fake native artifact in a build subdirectory
    artifact_dir = tmp_path / "target" / "debug" / "build" / "mylib-abc123" / "out"
    artifact_dir.mkdir(parents=True)
    fake_so = tmp_path / "target" / "debug" / "libfake.so"
    fake_so.write_bytes(b"\x7fELF")  # plausible ELF magic, no real content

    violation_event = SandboxTelemetryEvent(
        type="native-artifact-escalation",
        severity=Severity.CRITICAL,
        message="suspicious strings in libfake.so: socket",
    )
    detected_event = SandboxTelemetryEvent(
        type="cargo-native-artifact-detected",
        severity=Severity.MEDIUM,
        message=f"native binary found in build output: {fake_so.name}",
    )

    def fake_collect(target_debug: Path):  # type: ignore[override]
        yield fake_so

    def fake_inspect(artifact: Path):
        return [detected_event, violation_event], True

    with (
        patch("emergency_room.sandbox._collect_native_artifacts", side_effect=fake_collect),
        patch("emergency_room.sandbox._inspect_native_artifact", side_effect=fake_inspect),
    ):
        events, violation, needs_hifi = asyncio.run(
            post_cargo_build_inspection(tmp_path)
        )

    assert violation is True
    assert needs_hifi is True
    event_types = [e.type for e in events]
    assert "cargo-native-escalation-pending-hifi" in event_types
    escalation = next(e for e in events if e.type == "cargo-native-escalation-pending-hifi")
    assert escalation.severity == Severity.CRITICAL
