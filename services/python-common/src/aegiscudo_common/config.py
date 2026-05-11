from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_address
from pathlib import Path
from urllib.parse import urlparse


class MissingConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServiceStartupSettings:
    service_name: str
    environment: str
    fail_closed: bool
    telemetry_endpoint: str | None


COMMON_REQUIRED_ENV_VARS: tuple[str, ...] = (
    "DATABASE_URL",
    "REDIS_URL",
    "AEGISCUDO_TELEMETRY_ENDPOINT",
)

AI_PROVIDER_ENV_VARS: tuple[str, ...] = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "OPENROUTER_API_KEY",
    "LOCAL_LLM_BASE_URL",
)

GHSA_REQUIRED_ENV_VARS: tuple[str, ...] = ("GITHUB_TOKEN",)
LOCAL_LLM_ALLOWED_IPV4_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)


def load_workspace_env_file(
    *,
    env_file: Path | None = None,
    override: bool = False,
) -> bool:
    resolved_path = env_file or Path(__file__).resolve().parents[4] / ".env"
    if not resolved_path.is_file():
        return False

    for raw_line in resolved_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].strip()
        if "=" not in stripped:
            continue

        name, raw_value = stripped.split("=", 1)
        key = name.strip()
        if not key:
            continue
        if not override and empty_to_none(os.environ.get(key)) is not None:
            continue
        os.environ[key] = _parse_env_value(raw_value)

    return True


def _parse_env_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    comment_index = value.find(" #")
    if comment_index != -1:
        value = value[:comment_index]
    return value.strip()


def service_startup_settings(
    service_name: str,
    *,
    env: Mapping[str, str] | None = None,
    required_vars: Sequence[str] = (),
) -> ServiceStartupSettings:
    values = os.environ if env is None else env
    validate_required_environment(required_vars, env=values)
    return ServiceStartupSettings(
        service_name=service_name,
        environment=values.get("AEGISCUDO_ENV", "development"),
        fail_closed=parse_bool(values.get("AEGISCUDO_FAIL_CLOSED"), default=True),
        telemetry_endpoint=empty_to_none(values.get("AEGISCUDO_TELEMETRY_ENDPOINT")),
    )


def validate_required_environment(
    required_vars: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
) -> None:
    values = os.environ if env is None else env
    missing = [name for name in required_vars if not empty_to_none(values.get(name))]
    if missing:
        joined = ", ".join(sorted(missing))
        raise MissingConfigurationError(f"missing required environment variables: {joined}")


def validate_ai_provider_bootstrap(*, env: Mapping[str, str] | None = None) -> None:
    values = os.environ if env is None else env
    local_llm_base_url = empty_to_none(values.get("LOCAL_LLM_BASE_URL"))
    if local_llm_base_url:
        validate_local_llm_base_url(local_llm_base_url, environment=values.get("AEGISCUDO_ENV"))
    if not any(empty_to_none(values.get(name)) for name in AI_PROVIDER_ENV_VARS):
        joined = ", ".join(AI_PROVIDER_ENV_VARS)
        raise MissingConfigurationError(
            "at least one AI provider credential or LOCAL_LLM_BASE_URL is required before "
            f"executing AI jobs; checked {joined}"
        )


def require_fail_closed_for_enforcement(*, env: Mapping[str, str] | None = None) -> None:
    values = os.environ if env is None else env
    if not parse_bool(values.get("AEGISCUDO_FAIL_CLOSED"), default=True):
        raise MissingConfigurationError(
            "AEGISCUDO_FAIL_CLOSED must remain true for enforcement-mode request-time services"
        )


def validate_local_llm_base_url(url: str, *, environment: str | None = None) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise MissingConfigurationError("LOCAL_LLM_BASE_URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise MissingConfigurationError("LOCAL_LLM_BASE_URL must not include userinfo")
    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "localhost.localdomain"}:
        return
    try:
        address = ip_address(hostname)
    except ValueError as error:
        raise MissingConfigurationError(
            "LOCAL_LLM_BASE_URL must use loopback or RFC1918 hostnames"
        ) from error
    if address.is_loopback:
        return
    if address.version == 4 and any(
        address in network for network in LOCAL_LLM_ALLOWED_IPV4_NETWORKS
    ):
        return
    if environment and environment.lower() != "development":
        raise MissingConfigurationError("LOCAL_LLM_BASE_URL must not point outside local networks")
    raise MissingConfigurationError("LOCAL_LLM_BASE_URL must use loopback or RFC1918 networking")


def parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "f", "no", "n", "off"}:
        return False
    raise MissingConfigurationError("invalid boolean value")


def empty_to_none(value: str | None) -> str | None:
    if value is None or value.strip() == "":
        return None
    return value
