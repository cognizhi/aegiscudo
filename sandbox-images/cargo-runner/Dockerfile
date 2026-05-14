FROM rust:1-slim

# Install binutils for strings/nm/readelf and clean up apt cache
RUN apt-get update \
    && apt-get install -y --no-install-recommends binutils \
    && rm -rf /var/lib/apt/lists/*

# Install rustfilt for Rust symbol demangling (best-effort)
RUN cargo install rustfilt --quiet 2>/dev/null || true

# Create an unprivileged sandbox user
RUN useradd --create-home --uid 10001 --shell /bin/sh sandbox

USER sandbox
WORKDIR /sandbox

ENTRYPOINT ["cargo", "--version"]
