FROM rust:1.99.1-bookworm@sha256:1cf87f5f66e57e896041fa6a125ae5a30a971f258274497e768f8036858de28c AS builder

WORKDIR /workspace
COPY . .

RUN rustup target add wasm32-wasip1 \
    && cargo build --locked --release --target wasm32-wasip1 -p envoy-libperfusion

FROM scratch

COPY --from=builder /workspace/target/wasm32-wasip1/release/envoy_libperfusion.wasm /plugin.wasm
