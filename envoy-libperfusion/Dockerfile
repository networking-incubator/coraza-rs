FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS builder

WORKDIR /workspace
COPY . .

RUN rustup target add wasm32-wasip1 \
    && cargo build --locked --release --target wasm32-wasip1 -p envoy-libperfusion

FROM scratch

COPY --from=builder /workspace/target/wasm32-wasip1/release/envoy_libperfusion.wasm /plugin.wasm
