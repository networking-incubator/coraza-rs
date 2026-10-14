FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS builder

WORKDIR /workspace
COPY . .

RUN rustup target add wasm32-wasip1 \
    && cargo build --locked --release --target wasm32-wasip1 -p envoy-libperfusion

FROM scratch

COPY --from=builder /workspace/target/wasm32-wasip1/release/envoy_libperfusion.wasm /plugin.wasm
