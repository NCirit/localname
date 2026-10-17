# Boots systemd as PID 1 to exercise `localname daemon` from a source build and from the
# packaged unit (M6).
FROM rust:1.88-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY schemas ./schemas
COPY skills ./skills
COPY examples ./examples
COPY packaging/systemd ./packaging/systemd

RUN --mount=type=cache,id=localname-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=localname-daemon-target,target=/build/target \
    cargo build --locked --release --bin localname && cp target/release/localname /build/localname

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dnsutils procps \
    && rm -rf /var/lib/apt/lists/*
# A source build: root-owned, outside any package path.
COPY --from=build /build/localname /opt/build/localname
COPY packaging/systemd /opt/packaging
COPY tests/daemon/linux-check.sh /usr/local/bin/check
COPY tests/daemon/linux-after-reboot.sh /usr/local/bin/after-reboot
COPY tests/daemon/linux-packaged.sh /usr/local/bin/packaged
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/lib/systemd/systemd"]
