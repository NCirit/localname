# Images for the OpenWrt adapter matrix (M3c): an OpenWrt router that trusts a test-only
# SSH key, and a Debian host with localname, OpenSSH, and a DHCP client.
FROM rust:1.88-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY schemas ./schemas
COPY skills ./skills
COPY examples ./examples
RUN --mount=type=cache,id=localname-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=localname-router-target,target=/build/target \
    cargo build --locked --release --bin localname && cp target/release/localname /build/localname

FROM debian:bookworm-slim AS keys
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && ssh-keygen -q -t ed25519 -N '' -C localname-test -f /id_ed25519

FROM openwrt/rootfs:x86-64-24.10.3 AS openwrt
COPY --from=keys /id_ed25519.pub /etc/dropbear/authorized_keys
COPY --chmod=0644 tests/router/network.uci /etc/config/network
RUN chmod 0600 /etc/dropbear/authorized_keys
CMD ["/sbin/init"]

FROM debian:bookworm-slim AS host
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client busybox \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/localname /usr/local/bin/localname
COPY --from=keys --chmod=0600 /id_ed25519 /root/.ssh/id_ed25519
COPY --chmod=0755 tests/router/lease.sh /usr/local/bin/lease
CMD ["sleep", "infinity"]
