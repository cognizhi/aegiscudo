from __future__ import annotations

import logging as stdlib_logging
import re
from collections.abc import Mapping
from typing import Any, cast

import structlog
from structlog.typing import EventDict, WrappedLogger

REDACTED = "[REDACTED]"

SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "auth_header",
    "authorization",
    "client_secret",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
)

SENSITIVE_EXACT_KEYS = frozenset({"env", "environ", "environment"})

AUTH_SCHEME_PATTERN = re.compile(r"(?i)\b(bearer|basic|token)\s+([a-z0-9._~+/=-]+)")
HEADER_SECRET_PATTERN = re.compile(
    r"(?i)\b(authorization|x-api-key|cookie|set-cookie)\s*(:)\s*([^\r\n,;]+)"
)
KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|auth[_-]?token|client[_-]?secret|password|secret|token)"
    r"\s*(=)\s*([^\s,;]+)"
)
JSON_SECRET_PATTERN = re.compile(
    r"(?i)([\"'](?:api[_-]?key|auth[_-]?token|client[_-]?secret|password|secret|token)[\"']"
    r"\s*:\s*)[\"'][^\"']+[\"']"
)
NPM_AUTH_TOKEN_PATTERN = re.compile(r"(?i)(_authToken\s*=\s*)([^\s,;]+)")
URL_USERINFO_PATTERN = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@")
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
MAX_REDACTION_DEPTH = 20


class RedactingFilter(stdlib_logging.Filter):
    def filter(self, record: stdlib_logging.LogRecord) -> bool:
        record.msg = redact_sensitive_data(record.msg)
        if record.args:
            record.args = redact_sensitive_data(record.args)
        return True


def configure_logging(service_name: str, log_level: str = "INFO") -> None:
    level = _parse_log_level(log_level)
    stdlib_logging.basicConfig(format="%(message)s", level=level)
    _install_stdlib_redaction_filter()

    def add_service_name(
        _logger: WrappedLogger,
        _method_name: str,
        event_dict: EventDict,
    ) -> EventDict:
        event_dict.setdefault("service", service_name)
        return event_dict

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            redact_event,
            add_service_name,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def redact_event(
    _logger: WrappedLogger,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    return cast(EventDict, redact_mapping(event_dict))


def redact_mapping(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _redact_value(key, value, depth=0) for key, value in payload.items()}


def redact_sensitive_data(value: Any) -> Any:
    return _redact_value("", value, depth=0)


def _redact_value(key: str, value: Any, *, depth: int) -> Any:
    if depth > MAX_REDACTION_DEPTH:
        return REDACTED
    if _is_sensitive_key(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {
            item_key: _redact_value(item_key, item_value, depth=depth + 1)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(key, item, depth=depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(key, item, depth=depth + 1) for item in value)
    if isinstance(value, str):
        return _redact_sensitive_string(value)
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in SENSITIVE_EXACT_KEYS or any(
        fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS
    )


def _redact_sensitive_string(value: str) -> str:
    redacted = value
    redacted = PRIVATE_KEY_PATTERN.sub(REDACTED, redacted)
    redacted = URL_USERINFO_PATTERN.sub(
        lambda match: f"{match.group(1)}{REDACTED}:{REDACTED}@",
        redacted,
    )
    redacted = JSON_SECRET_PATTERN.sub(lambda match: f"{match.group(1)}\"{REDACTED}\"", redacted)
    redacted = NPM_AUTH_TOKEN_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    redacted = HEADER_SECRET_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)} {REDACTED}",
        redacted,
    )
    redacted = KEY_VALUE_SECRET_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}",
        redacted,
    )
    redacted = AUTH_SCHEME_PATTERN.sub(lambda match: f"{match.group(1)} {REDACTED}", redacted)
    return redacted


def _parse_log_level(log_level: str) -> int:
    level = getattr(stdlib_logging, log_level.upper(), None)
    return level if isinstance(level, int) else stdlib_logging.INFO


def _install_stdlib_redaction_filter() -> None:
    root_logger = stdlib_logging.getLogger()
    root_has_filter = any(
        isinstance(existing_filter, RedactingFilter) for existing_filter in root_logger.filters
    )
    if not root_has_filter:
        root_logger.addFilter(RedactingFilter())
    for handler in root_logger.handlers:
        handler_has_filter = any(
            isinstance(existing_filter, RedactingFilter) for existing_filter in handler.filters
        )
        if not handler_has_filter:
            handler.addFilter(RedactingFilter())
