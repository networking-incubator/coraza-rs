FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS builder

WORKDIR /workspace
COPY . .

RUN rustup target add wasm32-wasip1 \
    && cargo build --locked --release --target wasm32-wasip1 -p envoy-libperfusion

FROM scratch

COPY --from=builder /workspace/target/wasm32-wasip1/release/envoy_libperfusion.wasm /plugin.wasm
