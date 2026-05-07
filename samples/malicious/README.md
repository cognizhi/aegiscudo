# Malicious Package Fixtures

Security test fixtures for Aegiscudo local testing. Each sample demonstrates a
common supply-chain exfiltration pattern: collect `env` at install/build/import
time and POST the payload to a remote URL.

**These fixtures are inert by default.** The exfiltration target is always
`http://localhost:9999/collect`. Nothing leaves the machine unless you
deliberately start a receiver and execute one of the packages in an uncontrolled
environment. Run all of them inside the sandbox profiles in `sandbox-images/`.

## Packages

| Directory | Ecosystem | Attack vector |
|-----------|-----------|---------------|
| `npm/env-snoop/` | npm | `preinstall` lifecycle hook |
| `pypi/env-snoop/` | PyPI | `setup.py` custom install command + `__init__.py` import-time execution |
| `rust/env-snoop/` | Cargo | `build.rs` build-time execution |
| `java/env-snoop/` | Maven/JAR | Static class initializer fired on class load |

---

## Step-by-step Testing Guide

### Prerequisites

| Tool | Minimum version | Check |
|------|-----------------|-------|
| Node.js / npm | 18+ | `node --version` |
| Python | 3.8+ | `python --version` |
| Rust / Cargo | stable | `cargo --version` |
| Java (JDK) | 11+ | `java --version` |
| Maven | 3.8+ | `mvn --version` |

All commands below are run from the **repository root** (`aegiscudo/`).

---

### Step 1 — Build the packages (if not already built)

```bash
make -C samples/malicious build
```

Expected output — one confirmation line per ecosystem:

```
[npm]  built: samples/malicious/npm/env-snoop/env-snoop-1.0.0.tgz
[pypi] built: samples/malicious/pypi/env-snoop/dist/env_snoop-1.0.0.tar.gz
[rust] built: samples/malicious/rust/env-snoop/target/debug/libenv_snoop.rlib
[java] built: samples/malicious/java/env-snoop/target/env-snoop-1.0.0.jar
```

---

### Step 2 — Start the exfil listener

Open a **dedicated terminal** and leave it running throughout the tests.

```bash
python samples/malicious/listener/listener.py
```

Expected output:

```
Aegiscudo exfil listener — http://localhost:9999  (Ctrl-C to stop)
```

Every package below will POST its captured environment to this listener.
Each hit prints a `=== EXFIL RECEIVED ===` block with the full JSON payload.

---

### Step 3 — Test the npm package

The malicious code runs via the `preinstall` npm lifecycle hook — triggered
automatically by `npm install`.

```bash
# Use --prefix so npm installs into a completely separate directory and never
# touches the pnpm workspace at the repo root (plain `npm install` inside a
# pnpm workspace hits an arborist symlink bug and fails with a null-matches error).
npm install --prefix /tmp/test-npm-exfil \
  "$(pwd)/samples/malicious/npm/env-snoop/env-snoop-1.0.0.tgz"
```

**What to expect in the listener terminal:**

```
=== EXFIL RECEIVED ===
Path : /collect
From : ('127.0.0.1', <port>)
{
  "source": "npm-preinstall",
  "package": "env-snoop@1.0.0",
  "env": { "HOME": "...", "PATH": "...", ... }
}
======================
```

**What to look for in the npm package source:**

- `package.json` → `"scripts": { "preinstall": "node preinstall.js" }` — the hook declaration
- `preinstall.js` → `http.request(...)` to `localhost:9999/collect` — the exfil call

**Scan the tarball with Surgeon** (static analysis — no install needed):

```bash
mkdir -p /tmp/surgeon-npm
tar -xzf samples/malicious/npm/env-snoop/env-snoop-1.0.0.tgz \
  -C /tmp/surgeon-npm --strip-components=1
cargo run -p surgeon -- --scan-dir /tmp/surgeon-npm
rm -rf /tmp/surgeon-npm
```

Expected indicators: `npm-install-lifecycle-hook` (critical), `node-outbound-http` (high), `node-env-read` (high).

Clean up:

```bash
rm -rf /tmp/test-npm-exfil
```

---

### Step 4 — Test the PyPI package

Two independent attack vectors are present: install-time (`setup.py`) and
import-time (`__init__.py`).

#### 4a — Install-time exfil

```bash
# Use a throwaway virtual environment.
python -m venv /tmp/test-pypi-exfil
source /tmp/test-pypi-exfil/bin/activate
pip install samples/malicious/pypi/env-snoop/dist/env_snoop-1.0.0.tar.gz
```

The listener receives one POST during `pip install` from the `setup.py`
`_MaliciousInstall.run()` override.

#### 4b — Import-time exfil

With the package still installed in the venv, open a Python REPL or run:

```bash
python -c "import env_snoop"
```

The listener receives a second POST the moment the import resolves — from the
top-level `_exfil()` call in `env_snoop/__init__.py`.

**What to look for in the PyPI package source:**

- `setup.py` → `class _MaliciousInstall(install)` overrides `run()` and calls `_exfil()` before delegating to the real installer
- `env_snoop/__init__.py` → bare `_exfil()` call at module scope — no function call needed from the consumer

**Scan the sdist with Surgeon** (static analysis — no install needed):

```bash
mkdir -p /tmp/surgeon-pypi
tar -xzf samples/malicious/pypi/env-snoop/dist/env_snoop-1.0.0.tar.gz \
  -C /tmp/surgeon-pypi --strip-components=1
cargo run -p surgeon -- --scan-dir /tmp/surgeon-pypi
rm -rf /tmp/surgeon-pypi
```

Expected indicators: `python-outbound-http` (high) and `python-env-read` (high) in both `setup.py` and `__init__.py`.

Clean up:

```bash
deactivate && rm -rf /tmp/test-pypi-exfil
```

---

### Step 5 — Test the Rust package

The malicious code runs in `build.rs` — executed by Cargo **at compile time**,
not at runtime.

```bash
cd samples/malicious/rust/env-snoop
cargo clean
cargo build
```

The listener receives a POST during the `cargo build` compilation step, before
any binary is produced.

**What to look for in the Rust package source:**

- `Cargo.toml` → `build = "build.rs"` — tells Cargo to run this file at compile time
- `build.rs` → `post_to_receiver()` using only `std::net::TcpStream` — no external crate required, so the dependency graph looks clean to a casual reviewer

**Scan the compiled rlib with Surgeon** (binary string extraction — no source needed):

Surgeon extracts printable ASCII string constants from the binary `.rlib` archive
and matches them against all rules. The `TcpStream::connect` symbol name embedded
in the compiled output triggers `rust-raw-network`.

```bash
mkdir -p /tmp/surgeon-rust-bin
cp target/debug/libenv_snoop.rlib /tmp/surgeon-rust-bin/
cargo run --manifest-path ../../../../Cargo.toml -p surgeon -- \
  --scan-dir /tmp/surgeon-rust-bin
rm -rf /tmp/surgeon-rust-bin
```

Expected indicators: `rust-raw-network` (critical) from the symbol table of the compiled library.

Return to repo root:

```bash
cd ../../../..
```

---

### Step 6 — Test the Java package

The malicious code lives in a `static { ... }` initializer block in
`EnvSnoop.java`. The JVM executes it the moment the class is loaded — before
`main()` or any method is called.

```bash
java -cp samples/malicious/java/env-snoop/target/env-snoop-1.0.0.jar \
     com.example.envsnoop.EnvSnoop
```

The listener receives a POST immediately on class load, before `main()` prints
its greeting.

**What to look for in the Java package source:**

- `EnvSnoop.java` → `static { exfil(); }` block at the top of the class — the unconditional trigger
- `exfil()` → `HttpURLConnection` POST to `localhost:9999/collect` with `System.getenv()` as payload

**Scan the JAR with Surgeon** (ZIP container + bytecode string extraction — no source needed):

Surgeon opens the JAR as a ZIP archive, iterates every `.class` entry, and
extracts string constants from the bytecode (constant pool). No Java source is
required — this is what Aegiscudo does at request time when a package is fetched.

```bash
mkdir -p /tmp/surgeon-java
cp samples/malicious/java/env-snoop/target/env-snoop-1.0.0.jar /tmp/surgeon-java/
cargo run -p surgeon -- --scan-dir /tmp/surgeon-java
rm -rf /tmp/surgeon-java
```

Expected output:

```json
{
  "indicators": [
    {
      "indicator_type": "java-outbound-http",
      "severity": "high",
      "file_path": "env-snoop-1.0.0.jar/com/example/envsnoop/EnvSnoop.class",
      "summary": "Java outbound HTTP connection",
      "details": {
        "destination": "http://localhost:9999/collect",
        "destination_encoding": "plaintext"
      }
    }
  ]
}
```

The `details` object is populated whenever Surgeon can extract contextual information
from the code surrounding a match:

| Field | Meaning |
|-------|---------|
| `destination` | Destination URL or `host:port` extracted from the surrounding context |
| `destination_encoding` | How it was found: `"plaintext"`, `"base64-decoded"`, or `"url-decoded"` |
| `destination_raw` | The pre-decode value, present when `destination_encoding` is not `"plaintext"` |
| `payload_hint` | What data appears to be transmitted (e.g., `process.env`, `System.getenv()`, `base64-encoded payload`) |

The `file_path` field names the entry inside the JAR so the exact class is identifiable.

---

### Step 7 — Verify no exfil when listener is down

Stop the listener (`Ctrl-C`) and repeat any of the steps above. Each package
silently swallows the connection error and completes normally — mimicking a real
attacker's "fail-open" approach that avoids alerting the victim.

---

### Step 8 — Clean up all build artefacts

```bash
make -C samples/malicious clean
```

---

## What Aegiscudo Should Detect

| Signal | Source |
|--------|--------|
| Lifecycle hook present (`preinstall`) | npm package.json static analysis |
| `os.environ` read + outbound HTTP at import time | PyPI static analysis |
| Network call in `build.rs` | Cargo static analysis |
| Static initializer with HTTP client | JAR class analysis |
| Outbound POST to external URL at install/build/import time | Cross-ecosystem heuristic |

---

## Scanning with Surgeon

Surgeon is Aegiscudo's static analysis engine. It accepts a directory and emits
`StaticEvidence` JSON with all detected indicators. Since version `0.1.0` it
handles **both source files and compiled binary artefacts**:

- **ZIP containers** (`.jar`, `.war`, `.ear`, `.whl`, `.zip`) — entries are
  unpacked in-memory and scanned individually.
- **Binary files** (`.class`, `.so`, `.rlib`, etc.) — printable ASCII string
  constants are extracted (like `strings(1)`) and matched against all rules.
  This surfaces URL literals, class references (`HttpURLConnection`), and
  method names (`getenv`) from compiled bytecode.

> All commands run from the **repository root** (`aegiscudo/`).

### npm

```bash
# Unpack the tarball, then scan the extracted directory.
mkdir -p /tmp/surgeon-npm
tar -xzf samples/malicious/npm/env-snoop/env-snoop-1.0.0.tgz \
  -C /tmp/surgeon-npm --strip-components=1
cargo run -p surgeon -- --scan-dir /tmp/surgeon-npm
```

Expected indicators: `npm-install-lifecycle-hook` (critical), `node-outbound-http` (high), `node-env-read` (high).

### PyPI

```bash
# Unpack the sdist, then scan the extracted directory.
mkdir -p /tmp/surgeon-pypi
tar -xzf samples/malicious/pypi/env-snoop/dist/env_snoop-1.0.0.tar.gz \
  -C /tmp/surgeon-pypi --strip-components=1
cargo run -p surgeon -- --scan-dir /tmp/surgeon-pypi
```

Expected indicators: `python-outbound-http` (high) in both `setup.py` and `__init__.py`, `python-env-read` (high) in both files.

### Rust

Surgeon scans source text, so point it at the unpacked crate source tree
(exclude the `target/` build directory — it contains compiled binaries that
exceed the file-size limit and produce noise).

```bash
# Copy only the source files into a clean staging directory.
mkdir -p /tmp/surgeon-rust
cp samples/malicious/rust/env-snoop/build.rs /tmp/surgeon-rust/
cp samples/malicious/rust/env-snoop/src/lib.rs /tmp/surgeon-rust/
cargo run -p surgeon -- --scan-dir /tmp/surgeon-rust
```

Expected indicators: `rust-raw-network` (critical) in `build.rs`.

### Java — scan the compiled JAR directly

No source required. Surgeon opens the JAR (a ZIP archive), iterates every
`.class` entry, extracts string constants from the bytecode, and runs all rules
over them.

```bash
mkdir -p /tmp/surgeon-java
cp samples/malicious/java/env-snoop/target/env-snoop-1.0.0.jar /tmp/surgeon-java/
cargo run -p surgeon -- --scan-dir /tmp/surgeon-java
```

Expected indicators: `java-outbound-http` (high) from `HttpURLConnection` and
`openConnection` string constants embedded in the compiled class file.

> **Why not `java-env-read` or `java-static-init`?**
> Both rules match source-level tokens (`System.getenv(` and `static {`).  In
> compiled bytecode the class reference is stored as `java/lang/System` and the
> method name as `getenv` in separate constant-pool entries.  The two strings
> are adjacent in the extracted output so `System.getenv(` does match, but the
> `static {` syntax only appears in source.  A dedicated class-file parser (not
> yet implemented) would be needed to detect `<clinit>` from bytecode metadata.

### Interpreting the output

```json
{
  "artifact_digest": { "algorithm": "sha256", "hex": "..." },
  "analyzer_version": "0.1.0",
  "rule_set_version": "mvp-static-rules-2026-05",
  "indicators": [
    {
      "indicator_type": "npm-install-lifecycle-hook",
      "severity": "critical",
      "file_path": "package.json",
      "start_line": 7,
      "end_line": 7,
      "redacted": true,
      "summary": "npm lifecycle hook — executes automatically during installation"
    }
  ]
}
```

- `indicator_type` maps to a named detection rule in `services/surgeon/src/lib.rs`
- `severity` is one of `critical`, `high`, `medium`, `low`
- `redacted: true` means the matching line is omitted from the output (adversarial content is never echoed back)
- `artifact_digest` is the SHA-256 of all scanned file content — used to tie the evidence to a specific artifact version in Triage Counter
- For binary files the `file_path` field uses the form `archive.jar/path/inside/Entry.class` so the entry inside the container is identifiable

### Current limitations

Surgeon today is a **standalone static scanner**. It is not yet wired end-to-end into the request-time enforcement path:

| Step | Status |
|------|--------|
| `cargo run -p surgeon -- --scan-dir <dir>` produces `StaticEvidence` JSON | **Working** |
| ZIP-container scanning (JAR, WHL) — indicators from compiled `.class` bytecode | **Working** |
| Binary string extraction for non-UTF-8 files (`.class`, `.so`, native exts) | **Working** |
| ZIP path-traversal detection in archive entries | **Working** |
| Full Java class-file constant-pool parser (structured extraction, not `strings`) | Not yet |
| `.tar` / `.tar.gz` container unpacking inside Surgeon | Not yet — unpack externally first |
| `StaticEvidence` stored in `static_analysis_reports` table | Phase 1B — not yet |
| Triage Counter reads `static_analysis_reports` at decision time | Implemented; depends on the row existing |
| `aedo scan npm --lockfile` / `aedo scan pnpm --lockfile` / `aedo scan pypi --requirements` | Parses coordinates from lockfiles; does not invoke Surgeon on archives yet |

To exercise the full path today, use the in-memory repository tests in Triage Counter:

```bash
cargo test -p triage-counter
```
