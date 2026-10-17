# Boots systemd as PID 1 to exercise the packaged unit, sysusers, and tmpfiles entries.
FROM rust:1.88-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY schemas ./schemas
COPY skills ./skills
COPY examples ./examples
COPY packaging/systemd ./packaging/systemd
RUN --mount=type=cache,id=localname-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=localname-systemd-target,target=/build/target \
    cargo build --locked --release --bin localname && cp target/release/localname /build/localname

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dnsutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/localname /usr/bin/localname
COPY packaging/systemd/localname.service /usr/lib/systemd/system/localname.service
COPY packaging/systemd/localname.sysusers /usr/lib/sysusers.d/localname.conf
COPY packaging/systemd/localname.tmpfiles /usr/lib/tmpfiles.d/localname.conf
COPY tests/systemd/check.sh /usr/local/bin/check
COPY tests/systemd/after-reboot.sh /usr/local/bin/after-reboot
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/lib/systemd/systemd"]
