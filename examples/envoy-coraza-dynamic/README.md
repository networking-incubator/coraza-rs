# Envoy Coraza native dynamic-module example

This example runs Coraza as Envoy's native dynamic-module filter. It includes a
Docker Compose configuration and a test harness. The checked-in `envoy.yaml` is
an uninspected baseline; do not deploy it unchanged.

## Requirements

Docker Compose, Python 3, Rust, clang/libclang, and curl with HTTP/2. The FTW
test also needs Go, Git, and network access. The derived-image test needs
`readelf`.

## Build and test

```sh
make build-envoy-dynamic
```

Use `make build-envoy-dynamic-crs` to embed the CRS rules. Run the integration
suite with:

```sh
make test-envoy-dynamic
```

Run the CRS FTW suite with:

```sh
make test-envoy-dynamic-ftw
```

This builds the CRS-enabled module. Set `FTW_INCLUDE_TESTS` to limit the suite
to selected cases.

## Derived image and rollback checks

Smoke-test a built image and compare the native and Wasm adapters with:

```sh
ENVOY_IMAGE=my-derived-image ENVOY_PLATFORM=linux/amd64 \
  python3 examples/envoy-coraza-dynamic/test.py derived-image
python3 examples/envoy-coraza-dynamic/test.py rollback
```

Set `ARCHITECTURE`, `PLATFORM`, and `PROFILE` to build the derived image with
Docker Buildx before the smoke test.

## Run the embedded-CRS demo

```sh
make run-envoy-dynamic-crs
```

This builds the CRS-enabled module, starts Envoy and the backend, and leaves
them running. It verifies that a sample SQL injection is blocked; the command
prints a repeatable test request, a log command, and the Compose command to stop
the demo.
