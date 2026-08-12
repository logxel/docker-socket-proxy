# Build stage — cross-compile static musl binary
FROM --platform=$TARGETPLATFORM rust:alpine AS builder

ARG TARGETPLATFORM
ARG TARGETARCH

RUN apk add --no-cache musl-dev perl make

WORKDIR /app

# Dummy source so the dependency build lands in its own cache layer, unaffected
# by source edits.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'pub mod config; pub mod error; pub mod proxy; pub mod security;' > src/lib.rs && \
    touch src/config.rs src/error.rs src/proxy.rs src/security.rs && \
    case "$TARGETARCH" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-musl  ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl  ;; \
      *)     echo "Unsupported arch: $TARGETARCH"; exit 1           ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    cargo build --release --locked --target "$RUST_TARGET" && \
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
    cargo build --release --locked --target "$RUST_TARGET" && \
    cp "target/$RUST_TARGET/release/docker-socket-proxy" /docker-socket-proxy && \
    strip /docker-socket-proxy

# Runtime stage — minimal scratch image
FROM scratch

COPY --from=builder /docker-socket-proxy /docker-socket-proxy

EXPOSE 2375

ENTRYPOINT ["/docker-socket-proxy"]
