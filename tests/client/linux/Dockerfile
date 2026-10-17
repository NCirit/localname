# Boots systemd with systemd-resolved to test client split DNS, including reboots and
# preservation of a VPN link's DNS and search domains.
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
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv systemd-resolved iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl enable systemd-resolved
COPY --from=build /build/localname /usr/bin/localname
COPY packaging/systemd/localname.service /usr/lib/systemd/system/localname.service
COPY packaging/systemd/localname.sysusers /usr/lib/sysusers.d/localname.conf
COPY packaging/systemd/localname.tmpfiles /usr/lib/tmpfiles.d/localname.conf
# A VPN-like link with its own DNS server, routing domain, and search domain, plus a
# global search domain: all must survive client setup, reboots, and rollback.
COPY --chmod=0644 tests/client/linux/fake-vpn.service tests/client/linux/stub-resolv.service /etc/systemd/system/
RUN printf '[Resolve]\nDomains=example.lan\n' > /etc/systemd/resolved.conf \
    && systemctl enable fake-vpn stub-resolv
COPY --chmod=0755 tests/client/linux/phase1.sh /usr/local/bin/phase1
COPY --chmod=0755 tests/client/linux/phase2.sh /usr/local/bin/phase2
COPY --chmod=0755 tests/client/linux/phase3.sh /usr/local/bin/phase3
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/lib/systemd/systemd"]
