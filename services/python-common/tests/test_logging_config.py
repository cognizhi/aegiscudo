import logging

from aegiscudo_common.logging_config import REDACTED, RedactingFilter, redact_event, redact_mapping


def test_redacts_nested_sensitive_keys_and_preserves_safe_values() -> None:
    payload = {
        "safe": "visible",
        "metadata": {
            "X-Api-Key": "abc123",
            "owner": "security",
            "items": [
                {"token": "tok_123"},
                {"name": "fixture"},
            ],
        },
    }

    assert redact_mapping(payload) == {
        "safe": "visible",
        "metadata": {
            "X-Api-Key": REDACTED,
            "owner": "security",
            "items": [
                {"token": REDACTED},
                {"name": "fixture"},
            ],
        },
    }


def test_redacts_auth_headers_and_private_keys_in_string_values() -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\nfake-key-material\n-----END PRIVATE KEY-----"
    payload = {
        "event": "request failed with Authorization: Bearer abc.def",
        "details": f"token=tok_123 body={private_key}",
    }

    redacted = redact_mapping(payload)

    assert redacted["event"] == "request failed with Authorization: [REDACTED]"
    assert redacted["details"] == "token=[REDACTED] body=[REDACTED]"


def test_redacts_common_secret_strings_without_sensitive_keys() -> None:
    redacted = redact_mapping(
        {
            "header": "X-Api-Key: abc123",
            "url": "url=https://user:pass@example.test/hook",
            "json": "payload={'api_key': 'abc123'}",
            "package_config": "//registry.npmjs.org/:_authToken=npm_secret",
        }
    )

    assert redacted["header"] == "X-Api-Key: [REDACTED]"
    assert redacted["url"] == "url=https://[REDACTED]:[REDACTED]@example.test/hook"
    assert redacted["json"] == "payload={'api_key': \"[REDACTED]\"}"
    assert redacted["package_config"] == "//registry.npmjs.org/:_authToken=[REDACTED]"


def test_stdlib_log_filter_redacts_message_and_args() -> None:
    record = logging.LogRecord(
        name="aegiscudo-test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="provider failed: %s",
        args=("https://user:pass@example.test Authorization: token ghp_secret",),
        exc_info=None,
    )

    assert RedactingFilter().filter(record)
    assert record.getMessage() == (
        "provider failed: https://[REDACTED]:[REDACTED]@example.test "
        "Authorization: [REDACTED]"
    )


def test_redacts_environment_dumps_by_default() -> None:
    assert redact_mapping({"environment": {"PATH": "/usr/bin", "HOME": "home-dir"}}) == {
        "environment": REDACTED,
    }


def test_structlog_processor_redacts_event_dict() -> None:
    redacted = redact_event(
        None,
        "info",
        {"event": "auth", "Authorization": "Basic abc123", "safe": "ok"},
    )

    assert redacted == {"event": "auth", "Authorization": REDACTED, "safe": "ok"}