FROM rustlang/rust:nightly-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /usr/src/app
COPY . .

RUN rustup target add x86_64-unknown-linux-musl \
 && cargo build --release --target x86_64-unknown-linux-musl \
 && strip target/x86_64-unknown-linux-musl/release/proxyko-proxy

FROM alpine:latest

RUN adduser -D -u 1000 proxyko

COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/proxyko-proxy /usr/local/bin/proxyko-proxy

USER proxyko

EXPOSE 8041

ENTRYPOINT ["/usr/local/bin/proxyko-proxy"]
