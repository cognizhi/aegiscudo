from typing import Any

from aegiscudo_common.logging_config import redact_mapping


def redact_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    return redact_mapping(payload)