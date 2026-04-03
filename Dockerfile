FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --bin sh-guard --bin sh-guard-mcp

FROM alpine:3.19
COPY --from=builder /build/target/release/sh-guard /usr/local/bin/
COPY --from=builder /build/target/release/sh-guard-mcp /usr/local/bin/
ENTRYPOINT ["sh-guard"]
