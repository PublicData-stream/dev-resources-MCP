# Native builds: run this Dockerfile separately on amd64 and arm64.
FROM rust:1.99.1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS build
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --workspace --bins --release --locked --jobs 2
RUN python3 scripts/collect-notices.py /notices

FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d AS runtime-base
LABEL org.opencontainers.image.source="https://github.com/PublicData-stream/dev-resources-MCP" \
    org.opencontainers.image.licenses="AGPL-3.0-only"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/blobs && chown -R 65532:65532 /data
COPY LICENSE THIRD-PARTY-NOTICES.md /usr/share/licenses/devres/
COPY --from=build /notices /usr/share/licenses/devres/dependencies/
USER 65532:65532
WORKDIR /data

FROM runtime-base AS probe
COPY --from=build /src/target/release/devres-probe /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/devres-probe"]

FROM runtime-base AS audit-worker
COPY --from=build /src/target/release/devres-audit-worker /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/devres-audit-worker"]

FROM runtime-base AS server
COPY --from=build /src/target/release/devres-server /src/target/release/devres-audit-worker /usr/local/bin/
EXPOSE 8080/tcp 4433/udp
ENTRYPOINT ["/usr/local/bin/devres-server"]
CMD ["/etc/devres/server.toml"]

# Preserve the original combined image for an unqualified docker build.
FROM server AS runtime
COPY --from=build /src/target/release/devres-probe /usr/local/bin/
