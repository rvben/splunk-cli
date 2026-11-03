FROM rust:1.90.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -j 2 && cp target/release/splunk-cli /splunk-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 dbus gnome-keyring && rm -rf /var/lib/apt/lists/*
COPY --from=build /splunk-cli /usr/local/bin/splunk-cli
COPY tests/live/check.py /test/check.py
COPY tests/live/entrypoint.sh /test/entrypoint.sh
ENTRYPOINT ["sh", "/test/entrypoint.sh"]
