# HTTPS trust-mode scenarios (M4b): ACME DNS-01 against Pebble, and the local CA in the
# Debian system trust store.
FROM rust:1.88-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY schemas ./schemas
COPY skills ./skills
COPY examples ./examples
COPY packaging/systemd ./packaging/systemd
RUN --mount=type=cache,id=localname-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=localname-https-target,target=/build/target \
    cargo build --locked --release --bin localname && cp target/release/localname /build/localname

FROM ghcr.io/letsencrypt/pebble:latest AS pebble

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl busybox \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/localname /usr/local/bin/localname
COPY --from=pebble /test/certs/pebble.minica.pem /etc/pebble/minica.pem
COPY --chmod=0755 tests/https/dns01-hook.sh /usr/local/bin/dns01-hook
COPY --chmod=0755 tests/https/common.sh /usr/local/lib/localname-test.sh
COPY --chmod=0755 tests/https/acme.sh /usr/local/bin/acme-scenario
COPY --chmod=0755 tests/https/local-ca.sh /usr/local/bin/local-ca-scenario
