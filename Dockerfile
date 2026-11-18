# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/omnirelease /omnirelease \
 && mkdir -p /out/cache /out/config

# ---- runtime ----------------------------------------------------------------------------
# distroless/cc ships glibc, libgcc and CA certificates, and runs as an unprivileged user.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /omnirelease /usr/local/bin/omnirelease
COPY --from=build --chown=nonroot:nonroot /out/cache /var/cache/omnirelease
COPY --from=build --chown=nonroot:nonroot /out/config /etc/omnirelease

ENV OMNIRELEASE_LISTEN=0.0.0.0:8080 \
    OMNIRELEASE_CACHE_DIR=/var/cache/omnirelease

VOLUME ["/var/cache/omnirelease"]
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/omnirelease"]
CMD ["serve"]
