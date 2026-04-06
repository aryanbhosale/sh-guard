FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --bin sh-guard --bin sh-guard-mcp

FROM alpine:3.21
LABEL org.opencontainers.image.source="https://github.com/aryanbhosale/sh-guard"
LABEL org.opencontainers.image.description="Semantic shell command safety classifier for AI coding agents — AST-based risk scoring in under 100 microseconds"
LABEL org.opencontainers.image.licenses="GPL-3.0-only"
LABEL org.opencontainers.image.title="sh-guard"
LABEL org.opencontainers.image.url="https://github.com/aryanbhosale/sh-guard"
LABEL org.opencontainers.image.documentation="https://github.com/aryanbhosale/sh-guard#readme"
LABEL org.opencontainers.image.vendor="aryanbhosale"
COPY --from=builder /build/target/release/sh-guard /usr/local/bin/
COPY --from=builder /build/target/release/sh-guard-mcp /usr/local/bin/
RUN adduser -D shguard
USER shguard
ENTRYPOINT ["sh-guard"]
