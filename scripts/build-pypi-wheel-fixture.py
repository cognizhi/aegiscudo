from __future__ import annotations

import base64
import csv
import hashlib
from io import StringIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipInfo, ZipFile


ROOT = Path(__file__).resolve().parents[1]
DIST_NAME = "aegiscudo_benign_pypi_fixture"
VERSION = "1.0.0"
WHEEL_NAME = f"{DIST_NAME}-{VERSION}-py3-none-any.whl"
OUTPUT = ROOT / "testdata" / "pypi" / "packages" / WHEEL_NAME
FIXED_TIMESTAMP = (2026, 5, 6, 0, 0, 0)


def main() -> None:
    entries = {
        f"{DIST_NAME}/__init__.py": b'__version__ = "1.0.0"\n',
        f"{DIST_NAME}/core.py": b"def answer() -> int:\n    return 42\n",
        f"{DIST_NAME}-{VERSION}.dist-info/METADATA": (
            "Metadata-Version: 2.4\n"
            "Name: aegiscudo-benign-pypi-fixture\n"
            "Version: 1.0.0\n"
            "Summary: Safe PyPI wheel fixture for Aegiscudo tests\n"
            "Requires-Python: >=3.12\n"
        ).encode(),
        f"{DIST_NAME}-{VERSION}.dist-info/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: aegiscudo-fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
    }
    record_path = f"{DIST_NAME}-{VERSION}.dist-info/RECORD"
    entries[record_path] = build_record(entries, record_path).encode()

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED) as wheel:
        for path in sorted(entries):
            info = ZipInfo(path, FIXED_TIMESTAMP)
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            wheel.writestr(info, entries[path])


def build_record(entries: dict[str, bytes], record_path: str) -> str:
    output = StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for path in sorted(entries):
        data = entries[path]
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([path, f"sha256={digest}", str(len(data))])
    writer.writerow([record_path, "", ""])
    return output.getvalue()


if __name__ == "__main__":
    main()
