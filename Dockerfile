FROM rust:1.83-slim AS builder

WORKDIR /build
COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin rdns \
    && mkdir -p /etc/rdns/zones /var/run/rdns \
    && chown rdns:rdns /var/run/rdns

COPY --from=builder /build/target/release/rdns /usr/local/bin/rdns
COPY --from=builder /build/target/release/rdns-control /usr/local/bin/rdns-control
COPY rdns.toml.example /etc/rdns/rdns.toml

EXPOSE 53/udp 53/tcp 853/tcp 9153/tcp

USER rdns
ENTRYPOINT ["/usr/local/bin/rdns"]
CMD ["-c", "/etc/rdns/rdns.toml"]
