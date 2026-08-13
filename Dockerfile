# Build stage — cross-compile static musl binary
# Pinned by digest so the build is reproducible; Dependabot raises the bump.
FROM rust:alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS builder

ARG TARGETARCH

# Feature set: "minimal" drops the optional YAML parser, "full" builds the
# crate's defaults. Minimal is the default here so a plain `docker build .`
# reproduces the published image that bare tags point at, even though the crate
# itself builds YAML in by default.
ARG VARIANT=minimal

RUN apk add --no-cache musl-dev perl make

WORKDIR /app

# Dummy source so the dependency build lands in its own cache layer, unaffected
# by source edits. The library is left empty rather than mirroring the real
# module list, which would need updating whenever a module is added.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    : > src/lib.rs && \
    case "$TARGETARCH" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-musl  ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl  ;; \
      *)     echo "Unsupported arch: $TARGETARCH"; exit 1           ;; \
    esac && \
    case "$VARIANT" in \
      full)    FEATURE_FLAGS=""                      ;; \
      minimal) FEATURE_FLAGS="--no-default-features" ;; \
      *)       echo "Unsupported variant: $VARIANT"; exit 1 ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    cargo build --release --locked --target "$RUST_TARGET" $FEATURE_FLAGS && \
    rm -rf src/ && \
    rm -rf "target/$RUST_TARGET/release/.fingerprint/docker-socket-proxy-"* && \
    rm -f  "target/$RUST_TARGET/release/docker-socket-proxy" && \
    rm -f  "target/$RUST_TARGET/release/deps/libdocker_socket_proxy-"* && \
    rm -f  "target/$RUST_TARGET/release/deps/docker_socket_proxy-"*

COPY src/ src/
RUN case "$TARGETARCH" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-musl  ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl  ;; \
    esac && \
    case "$VARIANT" in \
      minimal) FEATURE_FLAGS="--no-default-features" ;; \
      *)       FEATURE_FLAGS=""                      ;; \
    esac && \
    cargo build --release --locked --target "$RUST_TARGET" $FEATURE_FLAGS && \
    cp "target/$RUST_TARGET/release/docker-socket-proxy" /docker-socket-proxy

# Runtime stage — minimal scratch image
FROM scratch

ARG VERSION=dev
ARG REVISION=unknown
ARG VARIANT=minimal

# Which feature set this is, since a tag suffix is invisible once the image has
# been pulled by digest and the difference is functional: YAML allowlists parse
# only in "full".
LABEL io.logxel.features="$VARIANT"

LABEL org.opencontainers.image.title="docker-socket-proxy" \
      org.opencontainers.image.description="Secure, minimal Docker socket proxy that filters dangerous API endpoints" \
      org.opencontainers.image.source="https://github.com/logxel/docker-socket-proxy" \
      org.opencontainers.image.documentation="https://github.com/logxel/docker-socket-proxy/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.base.name="scratch"

COPY --from=builder /docker-socket-proxy /docker-socket-proxy

EXPOSE 2375

# The binary defaults to loopback, which would answer nothing outside this
# container. Exposure here is what the operator publishes with -p, so the
# wildcard is the useful default and the narrower one is theirs to set.
ENV DOCKER_PROXY_BIND=0.0.0.0

# The binary probes itself: there is no shell or curl here to call /healthz
# with. It reads DOCKER_PROXY_PORT and DOCKER_PROXY_BIND, so a custom port or
# address needs no change here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=2s --retries=3 \
    CMD ["/docker-socket-proxy", "--health-check"]

# No USER directive, deliberately. The proxy's only job is to open
# /var/run/docker.sock, which is typically root:docker 0660, so a fixed
# unprivileged UID would fail on most hosts and return 502 for every request.
# Run non-root by supplying the host's docker GID at run time instead:
#   docker run --user 65534:$(getent group docker | cut -d: -f3) ...
# The image carries no shell, package manager, or setuid binary, so UID 0 here
# grants nothing beyond the socket the operator already mounted.
ENTRYPOINT ["/docker-socket-proxy"]
