FROM rust:1.88-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY schemas ./schemas
COPY skills ./skills
COPY examples ./examples
RUN cargo build --locked --release --bin localname --example network_probe

FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --create-home localname
COPY --from=build /build/target/release/localname /usr/local/bin/localname
USER localname
EXPOSE 5354/udp 5354/tcp
ENTRYPOINT ["localname"]
CMD ["serve"]

FROM runtime AS network-test
COPY --from=build /build/target/release/examples/network_probe /usr/local/bin/network-probe
