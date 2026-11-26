# syntax=docker/dockerfile:1
# The skein binary: a node, plus the inbound listener for provider push and the health check. Build
# from the folder holding rowboat with its siblings rinse and bento (the workspace's path
# dependencies); skein/Dockerfile.dockerignore keeps the rest of that folder out of the context:
#   docker build -t rowboat -f rowboat/skein/Dockerfile .
#   docker run -p 8080:8080 -v skein-data:/data -v ./skein.toml:/etc/skein/skein.toml:ro rowboat
ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-trixie AS build
WORKDIR /src/rowboat
COPY rinse /src/rinse
COPY bento /src/bento
COPY rowboat /src/rowboat
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/rowboat/target \
    cargo build --release --locked -p skein \
 && cp target/release/skein /usr/local/bin/skein

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data skein \
 && mkdir -p /data /etc/skein && chown 10001:10001 /data
ENV SKEIN_CONFIG=/etc/skein/skein.toml
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["skein"]
CMD ["serve"]
COPY --from=build /usr/local/bin/skein /usr/local/bin/skein
