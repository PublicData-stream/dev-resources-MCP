# Native builds: run this Dockerfile separately on amd64 and arm64.
FROM rust:1.99.1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS build
ARG TARGETARCH
ARG TARGETVARIANT
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN cp -a /usr/local/cargo /tmp/cargo && cp -a /usr/local/rustup /tmp/rustup
ENV CARGO_HOME=/tmp/cargo RUSTUP_HOME=/tmp/rustup CARGO_TARGET_DIR=/tmp/rust/target \
    TMPDIR=/tmp XDG_CACHE_HOME=/tmp/cache PYTHONPYCACHEPREFIX=/tmp/python-cache
COPY . .
RUN --mount=type=cache,id=devres-registry,target=/tmp/cargo/registry,sharing=locked \
    --mount=type=cache,id=devres-target-${TARGETARCH}-${TARGETVARIANT},target=/tmp/rust/target,sharing=locked \
    cargo build --workspace --bins --release --locked --jobs 2 \
    && mkdir -p /tmp/build-output \
    && cp /tmp/rust/target/release/devres-server /tmp/rust/target/release/devres-probe \
          /tmp/rust/target/release/devres-audit-worker /tmp/rust/target/release/devres-pdf-worker /tmp/build-output/ \
    && python3 scripts/collect-notices.py /notices

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
COPY --from=build /tmp/build-output/devres-probe /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/devres-probe"]

FROM runtime-base AS audit-worker
COPY --from=build /tmp/build-output/devres-audit-worker /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/devres-audit-worker"]

FROM runtime-base AS server
USER root
RUN apt-get update && apt-get install -y --no-install-recommends rsync git \
    && rm -rf /var/lib/apt/lists/*
USER 65532:65532
COPY --from=build /tmp/build-output/devres-server /tmp/build-output/devres-audit-worker /tmp/build-output/devres-pdf-worker /usr/local/bin/
EXPOSE 8080/tcp 4433/udp
ENTRYPOINT ["/usr/local/bin/devres-server"]
CMD ["/etc/devres/server.toml"]

# Preserve the original combined image for an unqualified docker build.
FROM server AS runtime
COPY --from=build /tmp/build-output/devres-probe /usr/local/bin/
