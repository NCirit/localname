FROM rust:1.88-slim-bookworm AS build
ARG TARGETPLATFORM
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY schemas ./schemas
COPY skills ./skills
COPY examples ./examples
RUN --mount=type=cache,id=localname-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=localname-target-${TARGETPLATFORM},target=/build/target \
    cargo build --locked --release --bin localname --example network_probe \
    && cp target/release/localname /build/localname \
    && cp target/release/examples/network_probe /build/network-probe

FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --create-home localname
RUN mkdir -p /var/lib/localname && chown localname /var/lib/localname
COPY --from=build /build/localname /usr/local/bin/localname
COPY packaging/container-entrypoint.sh /usr/local/bin/container-entrypoint
USER localname
EXPOSE 5354/udp 5354/tcp
ENTRYPOINT ["localname"]
CMD ["serve"]

FROM runtime AS network-test
COPY --from=build /build/network-probe /usr/local/bin/network-probe

# DHCP server and client for the whole-home setup scenario (tests/network/setup.yml).
FROM network-test AS network-tools
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsmasq-base busybox \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /plan && chown localname /plan
USER localname
