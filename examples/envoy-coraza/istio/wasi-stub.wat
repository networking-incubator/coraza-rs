;; ENOSYS stubs for the WASI functions Envoy's v8 Proxy-Wasm host does not
;; implement before Envoy 1.40 (proxy-wasm-cpp-host PR #433 added host-side
;; stubs; Istio 1.30 ships Envoy 1.38.x, which predates it). The coraza
;; engine's filesystem-backed features (audit-log file sinks, file-backed
;; operators) reference these syscalls; without definitions the VM refuses to
;; load the module at all ("missing import: wasi_snapshot_preview1.*").
;;
;; test-istio.sh links these stubs into the built artifact with binaryen's
;; wasm-merge so one artifact loads on both host generations. Every stub
;; returns WASI errno 52 (ENOSYS); they exist only to satisfy the loader, and
;; nothing in the connector's validated configuration reaches them.
(module
  (func (export "fd_filestat_get") (param i32 i32) (result i32) (i32.const 52))
  (func (export "fd_readdir") (param i32 i32 i32 i64 i32) (result i32) (i32.const 52))
  (func (export "path_create_directory") (param i32 i32 i32) (result i32) (i32.const 52))
  (func (export "path_filestat_get") (param i32 i32 i32 i32 i32) (result i32) (i32.const 52))
  (func (export "path_unlink_file") (param i32 i32 i32) (result i32) (i32.const 52))
)
