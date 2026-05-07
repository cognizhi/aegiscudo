# Aegiscudo malicious fixture build — produces package archives and binaries
# for all four ecosystems.
#
# Usage:
#   make build        — build everything
#   make npm          — build npm tarball only
#   make pypi         — build PyPI sdist only
#   make rust         — build Rust binary only
#   make java         — build JAR only
#   make clean        — remove all build artefacts

.PHONY: build npm pypi rust java clean

ROOT := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

build: npm pypi rust java

# ---------------------------------------------------------------------------
# npm — produces npm/env-snoop/env-snoop-1.0.0.tgz
# ---------------------------------------------------------------------------
npm:
	cd "$(ROOT)npm/env-snoop" && npm pack --pack-destination .
	@echo "[npm] built: $(ROOT)npm/env-snoop/env-snoop-1.0.0.tgz"

# ---------------------------------------------------------------------------
# PyPI — produces pypi/env-snoop/dist/env_snoop-1.0.0.tar.gz
# ---------------------------------------------------------------------------
pypi:
	cd "$(ROOT)pypi/env-snoop" && python -m build --sdist --outdir dist/
	@echo "[pypi] built: $(ROOT)pypi/env-snoop/dist/env_snoop-1.0.0.tar.gz"

# ---------------------------------------------------------------------------
# Rust — produces rust/env-snoop/target/debug/env-snoop (binary)
#         NOTE: build.rs fires during this step; start the listener first if
#               you want to see the exfil attempt.
# ---------------------------------------------------------------------------
rust:
	cd "$(ROOT)rust/env-snoop" && cargo build 2>&1
	@echo "[rust] built: $(ROOT)rust/env-snoop/target/debug/libenv_snoop.rlib"

# ---------------------------------------------------------------------------
# Java — produces java/env-snoop/target/env-snoop-1.0.0.jar
# ---------------------------------------------------------------------------
java:
	cd "$(ROOT)java/env-snoop" && mvn -q package -DskipTests
	@echo "[java] built: $(ROOT)java/env-snoop/target/env-snoop-1.0.0.jar"

clean:
	rm -f  "$(ROOT)npm/env-snoop/"*.tgz
	rm -rf "$(ROOT)pypi/env-snoop/dist" "$(ROOT)pypi/env-snoop/*.egg-info"
	cd "$(ROOT)rust/env-snoop" && cargo clean 2>/dev/null || true
	rm -rf "$(ROOT)java/env-snoop/target"
