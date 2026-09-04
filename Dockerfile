# Build a small, static-ish image for self-hosting.
#   docker build -t confidential-file-merger .
#   docker run --rm -p 8080:8080 confidential-file-merger
#
# The container has no outbound network needs at runtime; you can run it with
# `--network none` if you only ever open it from the same host via a published port,
# or on an internal Docker network for LAN use.

FROM rust:1.94-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin merger
COPY --from=build /src/target/release/confidential_file_merger /usr/local/bin/confidential_file_merger
USER merger
EXPOSE 8080
# Bind to all interfaces inside the container; Docker's port mapping decides who can reach it.
ENV CFM_HOST=0.0.0.0 CFM_PORT=8080
ENTRYPOINT ["/usr/local/bin/confidential_file_merger"]
