# The bag reference relay, ac-relay (crates/ac-relay), as a container image you build yourself from this repository.
# From the repository root:
#
#   docker build -f deploy/docker/Dockerfile --build-arg AC_REV="$(git rev-parse HEAD)" -t bag-relay:local .
#
# or through deploy/docker/compose.yml, which builds it the same way (docs/self-host.md, "Run it with Docker").
#
# Two stages. The builder is the official Rust image of the toolchain rust-toolchain.toml pins (1.95.0, Debian 13
# "trixie"), which builds ac-relay with --release --locked, so every crate comes from Cargo.lock. The final image is
# distroless's cc image for Debian 13 (glibc and libgcc, no shell, no package manager), whose glibc matches the
# builder's, running as its nonroot user (65532). Both bases are pinned by tag and by the digest of a multi-platform
# index, so a build makes the image for the platform it runs on (linux/amd64 or linux/arm64); each digest was at least
# 7 days old when pinned:
#   rust:1.95.0-trixie, index digest f49565f1..., created 2026-05-20
#   gcr.io/distroless/cc-debian13:nonroot, index digest e792ab3d..., uploaded 2026-10-01
# Nothing else is downloaded into the image, and it needs no secret. It runs no backup: the store is one SQLite file
# in the volume /data, and docs/self-host.md, section 6, has the backup and restore.
# The relay listens on 0.0.0.0:7701 inside the container. It has no TLS of its own: a front you run carries HTTPS to it
# (docs/self-host.md, section 5).

FROM rust:1.95.0-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS build
# The image's toolchain, not a download: rust-toolchain.toml would make rustup add clippy, rustfmt and llvm-tools,
# which a release build does not use. The check below fails the build if the image's rustc is not the pinned one.
ENV RUSTUP_TOOLCHAIN=1.95.0 CARGO_TERM_COLOR=never
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN pinned="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)" \
 && rustc --version \
 && test "$(rustc --version | cut -d ' ' -f 2)" = "$pinned"
# The commit, as the final stage's revision label: the build compiles it in as ac_relay_build_info's rev
# (crates/ac-relay/src/metrics.rs), which reads `unknown` for anything but 7 to 40 lower-case hex digits.
ARG AC_REV=unknown
# The registry cache only speeds up the crate downloads (the crates are checked against Cargo.lock's checksums);
# target/ is not cached, so every build compiles from the sources it was given.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --locked -p ac-relay \
 && mkdir -p /out/data \
 && cp target/release/ac-relay /out/ac-relay

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
ARG AC_REV=unknown
LABEL org.opencontainers.image.title="ac-relay" \
      org.opencontainers.image.description="bag reference relay: publish, fetch and subscribe over HTTP and WebSocket, stored in SQLite" \
      org.opencontainers.image.revision="${AC_REV}"
COPY --from=build /out/ac-relay /ac-relay
# An empty /data owned by the nonroot user, so that a new named volume mounted there is writable by it.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 7701
ENTRYPOINT ["/ac-relay"]
CMD ["--bind", "0.0.0.0", "--port", "7701", "--db", "/data/relay.sqlite"]
