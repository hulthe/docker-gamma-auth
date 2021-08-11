##################
### BASE STAGE ###
##################
FROM rust:1.54 AS base

RUN cargo install strip_cargo_version
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools # required by the "ring" crate

WORKDIR /app

###########################
### STRIP_VERSION STAGE ###
###########################
FROM base AS strip_version

COPY Cargo.lock Cargo.toml ./
RUN strip_cargo_version


###################
### BUILD STAGE ###
###################
FROM base AS build

# Create dummy crate to build dependencies
RUN cargo init --bin .
COPY --from=strip_version /app/Cargo.* /app/
RUN cargo build --release --target x86_64-unknown-linux-musl

# Build the actual program
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN strip /app/target/x86_64-unknown-linux-musl/release/docker_gamma_auth


########################
### PRODUCTION STAGE ###
########################
FROM scratch

WORKDIR /

ENV RUST_LOG="info"
ENV TOKEN_EXPIRES="300"

# Copy application binary
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/docker_gamma_auth docker_gamma_auth

CMD ["/docker_gamma_auth"]