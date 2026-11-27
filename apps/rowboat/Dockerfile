# syntax=docker/dockerfile:1
# rowboat, the headless multi-tenant server. Build from the folder holding rowboat with its siblings
# rinse and bento (the workspace's path dependencies); Dockerfile.dockerignore next to this file
# keeps the rest of that folder out of the context:
#   docker build -t rowboat -f rowboat/apps/rowboat/Dockerfile .
# FEATURES=test-roots builds the container suite's image only (a test CA for the mail servers).
ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-trixie AS build
ARG FEATURES=""
WORKDIR /src/rowboat
COPY rinse /src/rinse
COPY bento /src/bento
COPY rowboat /src/rowboat
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/rowboat/target \
    cargo build --release --locked -p rowboat --features "${FEATURES}" \
 && cp target/release/rowboat /usr/local/bin/rowboat

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data rowboat \
 && mkdir -p /data /secrets /cache /etc/rowboat \
 && chown 10001:10001 /data /secrets /cache \
 && chmod 0700 /data /secrets /cache
ENV ROWBOAT_CONFIG=/etc/rowboat/rowboat.toml
USER 10001:10001
VOLUME ["/data", "/secrets"]
EXPOSE 8080 4400-4499/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["rowboat"]
CMD ["serve"]
COPY --from=build /usr/local/bin/rowboat /usr/local/bin/rowboat
