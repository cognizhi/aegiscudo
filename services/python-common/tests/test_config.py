import os
from pathlib import Path

import pytest
from aegiscudo_common.config import (
    MissingConfigurationError,
    load_workspace_env_file,
    require_fail_closed_for_enforcement,
    service_startup_settings,
    validate_ai_provider_bootstrap,
    validate_local_llm_base_url,
    validate_required_environment,
)


def test_service_settings_default_to_fail_closed() -> None:
    settings = service_startup_settings("triage-counter", env={})

    assert settings.fail_closed is True
    assert settings.environment == "development"


def test_explicit_empty_env_does_not_read_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgres://ambient-secret@example.invalid/db")

    with pytest.raises(MissingConfigurationError, match="DATABASE_URL"):
        validate_required_environment(["DATABASE_URL"], env={})


def test_required_environment_reports_missing_names() -> None:
    with pytest.raises(MissingConfigurationError, match="DATABASE_URL"):
        validate_required_environment(["DATABASE_URL", "REDIS_URL"], env={"REDIS_URL": "redis://"})


def test_ai_provider_bootstrap_accepts_local_provider() -> None:
    validate_ai_provider_bootstrap(env={"LOCAL_LLM_BASE_URL": "http://localhost:11434"})


def test_local_llm_url_rejects_public_hosts() -> None:
    with pytest.raises(MissingConfigurationError, match="LOCAL_LLM_BASE_URL"):
        validate_local_llm_base_url("https://models.example.com", environment="development")


def test_local_llm_url_accepts_private_hosts() -> None:
    validate_local_llm_base_url("http://192.168.1.10:8000", environment="development")


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://192.0.2.1:11434",
        "http://[fe80::1]:11434",
        "http://user:pass@127.0.0.1:11434",
    ],
)
def test_local_llm_url_rejects_ssrf_and_userinfo_cases(url: str) -> None:
    with pytest.raises(MissingConfigurationError, match="LOCAL_LLM_BASE_URL"):
        validate_local_llm_base_url(url, environment="development")


def test_ai_provider_bootstrap_rejects_empty_provider_set() -> None:
    with pytest.raises(MissingConfigurationError, match="AI provider"):
        validate_ai_provider_bootstrap(env={})


def test_enforcement_requires_fail_closed() -> None:
    with pytest.raises(MissingConfigurationError, match="AEGISCUDO_FAIL_CLOSED"):
        require_fail_closed_for_enforcement(env={"AEGISCUDO_FAIL_CLOSED": "false"})


def test_invalid_boolean_errors_do_not_echo_raw_values() -> None:
    with pytest.raises(MissingConfigurationError) as error:
        service_startup_settings("triage-counter", env={"AEGISCUDO_FAIL_CLOSED": "token-like"})

    assert "token-like" not in str(error.value)


def test_load_workspace_env_file_reads_missing_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        'OPENROUTER_API_KEY=dotenv-openrouter\nDATABASE_URL="postgres://dotenv.example/db"\n',
        encoding="utf-8",
    )
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    loaded = load_workspace_env_file(env_file=env_file)

    assert loaded is True
    assert os.environ["OPENROUTER_API_KEY"] == "dotenv-openrouter"
    assert os.environ["DATABASE_URL"] == "postgres://dotenv.example/db"


def test_load_workspace_env_file_keeps_existing_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPENROUTER_API_KEY=dotenv-openrouter\n", encoding="utf-8")
    monkeypatch.setenv("OPENROUTER_API_KEY", "existing-openrouter")

    load_workspace_env_file(env_file=env_file)

    assert os.environ["OPENROUTER_API_KEY"] == "existing-openrouter"
