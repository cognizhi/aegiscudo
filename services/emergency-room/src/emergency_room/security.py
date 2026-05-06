from typing import Any

from aegiscudo_common.logging_config import redact_mapping as redact_sensitive_mapping


def redact_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    return redact_sensitive_mapping(payload)